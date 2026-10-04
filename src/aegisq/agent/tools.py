"""The migration agent's tools. Every safety rule is enforced here, whatever calls them.

Rules enforced in code:
  * only services with a ``managed`` block can be touched; the model never sees or chooses file paths
  * patches pass the guardrails (two directives, allowlisted values) at proposal AND at apply time
  * apply requires a human approval that is approved, unexpired, unused and bound to the exact diff hash
  * apply refuses if the live config changed since the proposal (drift)
  * the old config is backed up first and restored automatically if ``nginx -t`` or the reload fails
  * only one change may be in flight: a patch must be verified or rolled back before the next is applied
  * anything still unverified when the agent stops is rolled back by ``finalize()``
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegisq.agent import diagnose as dg
from aegisq.agent import guardrails as gr
from aegisq.agent.health import http_health, pq_check
from aegisq.agent.patchstore import PatchStore
from aegisq.agent.targets import NginxTarget, TargetUnavailable
from aegisq.config import AegisQConfig
from aegisq.filelock import FileLock, LockHeld
from aegisq.models import ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.risk import rank
from aegisq.workspace import Approval, Workspace, atomic_write


class ToolError(Exception):
    """A refusal or failure the agent should see (returned as an error tool_result)."""


@dataclass
class Proposal:
    id: str
    service: str
    original_sha: str
    new_text: str
    diff: str
    diff_sha256: str
    changes: list[str]
    rationale: str
    created_at: float
    branch: str | None = None
    approval_id: str | None = None
    state: str = "proposed"  # proposed | rejected | applied | failed


@dataclass
class ServiceState:
    unverified: bool = False
    last_good_backup: str | None = None
    outcome: str | None = None  # fixed | rejected | failed | rolled_back | skipped
    notes: list[str] = field(default_factory=list)


ApprovalWaiter = Callable[[Approval], Approval]


def _run(coro: Any) -> Any:
    """Run a coroutine from sync tool code, also when called inside a running loop (dashboard)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        return ex.submit(asyncio.run, coro).result()


class Toolbox:
    def __init__(
        self,
        ws: Workspace,
        cfg: AegisQConfig,
        report: ScanReport,
        *,
        actor: str = "agent",
        approval_waiter: ApprovalWaiter | None = None,
        verify_timeout: float = 5.0,
    ) -> None:
        self.ws = ws
        self.cfg = cfg
        self.report = report
        self.actor = actor
        self.scans: dict[str, ServiceScan] = {s.service.name: s for s in report.results}
        self.proposals: dict[str, Proposal] = {}
        self.state: dict[str, ServiceState] = {name: ServiceState() for name in self.scans}
        self.policy = gr.Policy(
            allowed_groups=cfg.agent.allowed_groups,
            require_classical_fallback=cfg.agent.require_classical_fallback,
            min_tls_version=cfg.agent.min_tls_version,
        )
        self.patches = PatchStore(ws.home / "patches" / "repo.git")
        self.verify_timeout = verify_timeout
        self._waiter = approval_waiter or (lambda a: ws.approvals.wait(a.id, timeout=cfg.agent.approval_timeout_s))

    # ---------------------------------------------------------- helpers
    def _audit(self, event: str, **data: Any) -> None:
        self.ws.audit.append(event, data, actor=self.actor)

    def _service(self, name: str) -> ServiceTarget:
        if not isinstance(name, str) or name not in self.scans:
            raise ToolError(f"unknown service {name!r}; call list_services for valid names")
        return self.scans[name].service

    def _target(self, name: str) -> NginxTarget:
        svc = self._service(name)
        try:
            return NginxTarget(svc)
        except TargetUnavailable as e:
            raise ToolError(str(e)) from None

    def _backup_dir(self, service: str) -> Path:
        d = self.ws.home / "backups" / service
        d.mkdir(parents=True, exist_ok=True)
        return d

    @contextmanager
    def _lock(self, service: str) -> Iterator[None]:
        lock = FileLock(self.ws.home / "locks" / f"{service}.lock", blocking=False)
        try:
            lock.acquire()
        except LockHeld:
            raise ToolError(f"{service} is locked by another AegisQ process") from None
        try:
            yield
        finally:
            lock.release()

    def _save_backup(self, service: str, text: str, reason: str) -> Path:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = self._backup_dir(service) / f"{ts}-{gr.sha256_text(text)[:12]}.conf"
        atomic_write(path, text, mode=0o600)
        manifest = self._backup_dir(service) / "manifest.jsonl"
        with manifest.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"path": path.name, "sha256": gr.sha256_text(text), "reason": reason, "ts": ts}) + "\n")
        return path

    def _last_backup(self, service: str) -> Path | None:
        st = self.state.get(service)
        if st and st.last_good_backup and Path(st.last_good_backup).exists():
            return Path(st.last_good_backup)
        manifest = self._backup_dir(service) / "manifest.jsonl"
        if not manifest.exists():
            return None
        lines = [json.loads(x) for x in manifest.read_text(encoding="utf-8").splitlines() if x.strip()]
        for entry in reversed(lines):
            if entry.get("reason") == "pre-apply":
                p = self._backup_dir(service) / entry["path"]
                if p.exists():
                    return p
        return None

    def _learn_stack(self, service: str, openssl: str | None) -> None:
        if not openssl:
            return
        facts = self.ws.load_json("facts.json") or {}
        facts.setdefault(service, {})["openssl"] = openssl
        self.ws.save_json("facts.json", facts)

    # ------------------------------------------------------------ tools
    def list_services(self) -> dict[str, Any]:
        facts = self.ws.load_json("facts.json") or {}
        scans = [_with_facts(s, facts) for s in self.scans.values()]
        ranking = rank(scans, self.cfg.risk)
        rows = []
        for r in ranking:
            svc = self.scans[r.service].service
            rows.append(
                {
                    "rank": r.rank,
                    "service": r.service,
                    "endpoint": svc.endpoint,
                    "protocol": svc.protocol.value,
                    "status": r.status,
                    "data_category": r.data_category,
                    "margin": r.margin,
                    "severity": r.severity,
                    "managed": svc.managed is not None,
                    "outcome_this_run": self.state[r.service].outcome,
                }
            )
        return {"z_years": self.cfg.risk.z_years, "services": rows}

    def read_config(self, service: str) -> dict[str, Any]:
        t = self._target(service)
        try:
            text = t.read_config()
        except TargetUnavailable as e:
            raise ToolError(str(e)) from None
        self._audit("config.read", service=service, sha256=gr.sha256_text(text))
        return {
            "service": service,
            "file": t.path.name,
            "sha256": gr.sha256_text(text),
            "directives": gr.current_directives(text),
            "config": text,
        }

    def propose_patch(
        self,
        service: str,
        diff: str | None = None,
        ssl_ecdh_curve: str | None = None,
        ssl_protocols: str | None = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        t = self._target(service)
        text = t.read_config()
        try:
            if not diff:
                diff = gr.make_patch(text, t.path.name, ssl_ecdh_curve=ssl_ecdh_curve, ssl_protocols=ssl_protocols)
            vp = gr.validate_patch(text, diff, self.policy)
        except gr.PatchRejected as e:
            self._audit("patch.rejected_by_guardrail", service=service, reason=str(e), diff=diff)
            raise ToolError(f"guardrail rejected the patch: {e}") from None
        pid = uuid.uuid4().hex[:10]
        p = Proposal(
            id=pid,
            service=service,
            original_sha=gr.sha256_text(text),
            new_text=vp.new_text,
            diff=vp.diff,
            diff_sha256=vp.diff_sha256,
            changes=vp.changes,
            rationale=rationale[:2000],
            created_at=time.time(),
        )
        p.branch = self.patches.record(
            service,
            pid,
            t.path.name,
            text,
            vp.new_text,
            vp.diff,
            f"{service}: AegisQ proposal {pid}\n\n{rationale[:500]}",
        )
        self.proposals[pid] = p
        self._audit(
            "patch.proposed",
            service=service,
            proposal_id=pid,
            diff=vp.diff,
            diff_sha256=vp.diff_sha256,
            changes=vp.changes,
            rationale=p.rationale,
            branch=p.branch,
        )
        return {"proposal_id": pid, "diff": vp.diff, "changes": vp.changes, "branch": p.branch}

    def request_approval(self, proposal_id: str) -> dict[str, Any]:
        p = self.proposals.get(proposal_id)
        if p is None:
            raise ToolError(f"unknown proposal {proposal_id!r}")
        if p.state != "proposed":
            raise ToolError(f"proposal {proposal_id} is {p.state}; propose a new patch")
        summary = "; ".join(p.changes)
        a = self.ws.approvals.create(
            p.service, p.id, p.diff, p.diff_sha256, summary, self.actor, self.cfg.agent.approval_ttl_s
        )
        p.approval_id = a.id
        self._audit(
            "approval.requested",
            service=p.service,
            proposal_id=p.id,
            approval_id=a.id,
            diff_sha256=p.diff_sha256,
            summary=summary,
        )
        try:
            decided = self._waiter(a)
        except BaseException:  # the run was stopped (Ctrl-C, dashboard Cancel): withdraw the request
            self.ws.approvals.cancel(a.id, "agent stopped before a decision")
            self._audit("approval.cancelled", service=p.service, approval_id=a.id, reason="agent stopped")
            raise
        if decided.status == "rejected":
            p.state = "rejected"
            self.state[p.service].outcome = "rejected"
        elif decided.status != "approved":
            p.state = "rejected"
            self.state[p.service].outcome = "skipped"
        self._audit(
            "approval.outcome",
            service=p.service,
            approval_id=a.id,
            status=decided.status,
            decided_by=decided.decided_by,
            reason=decided.reason,
        )
        return {
            "approval_id": a.id,
            "status": decided.status,
            "decided_by": decided.decided_by,
            "reason": decided.reason,
        }

    def apply_patch(self, proposal_id: str) -> dict[str, Any]:
        p = self.proposals.get(proposal_id)
        if p is None:
            raise ToolError(f"unknown proposal {proposal_id!r}")
        if p.state != "proposed" or not p.approval_id:
            raise ToolError(f"proposal {proposal_id} is {p.state} and has no usable approval; request_approval first")
        in_flight = [s for s, st in self.state.items() if st.unverified and s != p.service]
        if in_flight:
            raise ToolError(f"{in_flight[0]} has an applied but unverified change; verify or rollback it first")
        t = self._target(p.service)
        with self._lock(p.service):
            current = t.read_config()
            if gr.sha256_text(current) != p.original_sha:
                p.state = "failed"
                self._audit("patch.refused_drift", service=p.service, proposal_id=p.id)
                raise ToolError("the live config changed since the proposal; read_config and propose again")
            try:  # defence in depth: the guardrails run again on the live file
                vp = gr.validate_patch(current, p.diff, self.policy)
            except gr.PatchRejected as e:
                raise ToolError(f"guardrail rejected the patch at apply time: {e}") from None
            if vp.new_text != p.new_text or vp.diff_sha256 != p.diff_sha256:
                raise ToolError("patch content changed since approval; refusing")
            if not self.ws.approvals.consume(p.approval_id, p.diff_sha256):
                a = self.ws.approvals.get(p.approval_id)
                self._audit(
                    "patch.refused_no_approval",
                    service=p.service,
                    proposal_id=p.id,
                    approval_status=a.status if a else None,
                )
                raise ToolError(
                    f"no valid human approval for this exact diff (approval is {a.status if a else 'missing'})"
                )
            backup = self._save_backup(p.service, current, "pre-apply")
            self._audit("patch.applying", service=p.service, proposal_id=p.id, backup=backup.name)
            t.write_config(p.new_text)
            test = t.test()
            if not test.ok:
                t.write_config(current)
                retest = t.test()
                ver = t.version()
                diag = dg.diagnose(test.output, ver.output if ver else "")
                self._learn_stack(p.service, diag.openssl_version)
                p.state = "failed"
                st = self.state[p.service]
                st.outcome = "failed"
                st.notes.append(diag.root_cause)
                self._audit(
                    "patch.test_failed",
                    service=p.service,
                    proposal_id=p.id,
                    test_output=test.output[-4000:],
                    restored=True,
                    restored_config_test_ok=retest.ok,
                    diagnosis=diag.to_dict(),
                )
                return {
                    "applied": False,
                    "stage": "config_test",
                    "restored_previous_config": True,
                    "restored_config_passes_test": retest.ok,
                    "test_output": test.output[-3000:],
                    "diagnosis": diag.to_dict(),
                }
            reload = t.reload()
            if not reload.ok:
                t.write_config(current)
                re_reload = t.reload()
                p.state = "failed"
                self.state[p.service].outcome = "failed"
                self._audit(
                    "patch.reload_failed",
                    service=p.service,
                    proposal_id=p.id,
                    output=reload.output[-4000:],
                    restored=True,
                    restore_reload_ok=re_reload.ok,
                )
                return {
                    "applied": False,
                    "stage": "reload",
                    "restored_previous_config": True,
                    "reload_output": reload.output[-3000:],
                }
            p.state = "applied"
            st = self.state[p.service]
            st.unverified = True
            st.last_good_backup = str(backup)
            self._audit("patch.applied", service=p.service, proposal_id=p.id, test_output=test.output[-2000:])
            return {"applied": True, "config_test": "passed", "reloaded": True, "next": "call verify"}

    def verify(self, service: str) -> dict[str, Any]:
        svc = self._service(service)
        attempts = self.cfg.agent.verify_attempts
        pq_ok = health_ok = False
        pq_detail = health_detail = ""
        for i in range(attempts):
            pq_ok, pq_detail = _run(pq_check(svc, self.verify_timeout))
            h = _run(http_health(svc, self.verify_timeout))
            health_ok, health_detail = h.ok, h.detail
            if pq_ok and health_ok:
                break
            if i + 1 < attempts:
                time.sleep(self.cfg.agent.verify_interval_s)
        fixed = pq_ok and health_ok
        st = self.state.setdefault(service, ServiceState())
        if fixed:
            st.unverified = False
            st.outcome = "fixed"
            scan = self.scans[service]
            self.scans[service] = scan.model_copy(update={"status": Status.PQ_READY})
        self._audit(
            "service.verified" if fixed else "service.verify_failed",
            service=service,
            pq_ok=pq_ok,
            pq_detail=pq_detail,
            health_ok=health_ok,
            health_detail=health_detail,
        )
        out: dict[str, Any] = {
            "service": service,
            "fixed": fixed,
            "post_quantum_probe": {"ok": pq_ok, "detail": pq_detail},
            "health_check": {"ok": health_ok, "detail": health_detail},
        }
        if not fixed and st.unverified:
            out["next"] = "verification failed: call rollback"
        return out

    def rollback(self, service: str, reason: str = "requested") -> dict[str, Any]:
        t = self._target(service)
        backup = self._last_backup(service)
        if backup is None:
            return {"rolled_back": False, "reason": "no known-good backup recorded for this service"}
        with self._lock(service):
            good = backup.read_text(encoding="utf-8")
            current = t.read_config()
            if current != good:
                self._save_backup(service, current, "pre-rollback")
            t.write_config(good)
            test = t.test()
            reload = t.reload() if test.ok else None
        st = self.state.setdefault(service, ServiceState())
        st.unverified = False
        st.outcome = "rolled_back"
        self._audit(
            "patch.rolled_back",
            service=service,
            backup=backup.name,
            reason=reason,
            test_ok=test.ok,
            reload_ok=bool(reload and reload.ok),
        )
        return {
            "rolled_back": True,
            "restored": backup.name,
            "config_test_ok": test.ok,
            "reloaded": bool(reload and reload.ok),
        }

    def write_report(self) -> dict[str, Any]:
        from aegisq.report import generate_report

        paths = generate_report(self.ws, self.cfg)
        return {"written": [str(p.name) for p in paths]}

    def note(self, service: str, text: str) -> None:
        self.state.setdefault(service, ServiceState()).notes.append(text)

    def finalize(self) -> list[str]:
        """Code-enforced safety net: roll back anything the agent left applied but unverified."""
        rolled = []
        for name, st in self.state.items():
            if st.unverified:
                try:
                    self.rollback(name, reason="safety: agent stopped before verification passed")
                    rolled.append(name)
                except Exception as e:  # never let cleanup hide the original problem
                    self._audit("agent.safety_rollback_failed", service=name, error=str(e))
        if rolled:
            self._audit("agent.safety_rollback", services=rolled)
        return rolled


def _with_facts(scan: ServiceScan, facts: dict[str, dict[str, str]]) -> ServiceScan:
    f = facts.get(scan.service.name)
    if not f:
        return scan
    svc = scan.service.model_copy(update={"stack": {**scan.service.stack, **f}})
    return scan.model_copy(update={"service": svc})


def apply_facts(scans: list[ServiceScan], ws: Workspace) -> list[ServiceScan]:
    facts = ws.load_json("facts.json") or {}
    return [_with_facts(s, facts) for s in scans]
