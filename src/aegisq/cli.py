"""AegisQ command-line interface."""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Any, NoReturn

import click

from aegisq import __version__
from aegisq.config import AegisQConfig, load_config, load_env_file
from aegisq.models import ScanReport, ServiceScan, Status

EXIT_POLICY = 2

STATUS_STYLE = {
    "pq_ready": ("green", "PQ READY"),
    "classical": ("yellow", "CLASSICAL"),
    "tls12_only": ("red", "TLS1.2 ONLY"),
    "legacy_tls": ("red", "LEGACY TLS"),
    "plaintext": ("red", "PLAINTEXT"),
    "unreachable": ("bright_black", "UNREACHABLE"),
    "error": ("magenta", "ERROR"),
}


class Ctx:
    def __init__(self, config: str | None, home: str | None, env_file: tuple[Path, int] | None = None) -> None:
        self.env_file = env_file
        self.config_path = config
        self.cfg: AegisQConfig = load_config(config)
        if home:
            os.environ["AEGISQ_HOME"] = home
        self._ws: Any = None

    @property
    def ws(self) -> Any:
        if self._ws is None:
            from aegisq.workspace import Workspace

            self._ws = Workspace(self.cfg.home_path)
        return self._ws


pass_ctx = click.make_pass_decorator(Ctx)


def _fail(msg: str, code: int = 1) -> NoReturn:
    click.secho(f"error: {msg}", fg="red", err=True)
    sys.exit(code)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", type=click.Path(dir_okay=False), envvar="AEGISQ_CONFIG", help="YAML config file.")
@click.option("--home", type=click.Path(file_okay=False), help="Workspace directory (default .aegisq).")
@click.option("-v", "--verbose", count=True, help="More logging (-vv for debug).")
@click.version_option(__version__, prog_name="aegisq")
@click.pass_context
def main(ctx: click.Context, config: str | None, home: str | None, verbose: int) -> None:
    """AegisQ: find classical-only TLS/SSH services, rank them by Mosca risk, and migrate them to
    hybrid ML-KEM with a human approving every step."""
    logging.basicConfig(
        level=logging.WARNING - 10 * min(verbose, 2), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if hasattr(signal, "SIGBREAK"):  # Windows: a dashboard Cancel sends Ctrl-Break; clean up like Ctrl-C
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    env_file = load_env_file()  # before reading any setting, so .env can provide them
    try:
        ctx.obj = Ctx(config or os.environ.get("AEGISQ_CONFIG") or None, home, env_file)
    except ValueError as e:
        _fail(str(e))


# ----------------------------------------------------------------- scan ---


def _print_scan(report: ScanReport) -> None:
    w = max([len(r.service.name) for r in report.results] + [7])
    click.echo(f"{'SERVICE':<{w}}  {'ENDPOINT':<24} {'STATUS':<12} DETAIL")
    for r in sorted(report.results, key=lambda r: r.service.name):
        color, label = STATUS_STYLE[r.status.value]
        detail = ""
        if r.tls and r.tls.pq_ready:
            detail = f"{r.tls.pq_group}"
        elif r.tls and r.tls.modern_probe and r.tls.modern_probe.group:
            detail = f"{r.tls.modern_probe.version} {r.tls.modern_probe.group}"
        elif r.ssh:
            detail = r.ssh.negotiated_kex or (r.ssh.kex_algorithms[0] if r.ssh.kex_algorithms else "")
            detail = f"{detail} ({r.ssh.software})" if r.ssh.software else detail
        if r.errors:
            detail = (detail + "  " if detail else "") + r.errors[0][:80]
        click.echo(
            f"{r.service.name:<{w}}  {r.service.endpoint:<24} " + click.style(f"{label:<12}", fg=color) + f" {detail}"
        )
    s = report.summary()
    click.echo(
        f"\n{s['total']} services: {s['pq_ready']} PQ ready, {s['classical']} classical, {s['tls12_only']} TLS1.2, "
        f"{s['legacy_tls']} legacy, {s['plaintext']} plaintext, {s['unreachable']} unreachable, {s['error']} error"
    )


@main.command()
@click.argument("inventory", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(dir_okay=False), help="Also write the scan JSON here.")
@click.option("--json", "as_json", is_flag=True, help="Print JSON instead of a table.")
@click.option("--timeout", type=float, help="Per-probe timeout in seconds (default 5).")
@click.option("--concurrency", type=int, help="Parallel services (default 50).")
@click.option("--tls-backend", type=click.Choice(["native", "openssl"]), default="native", show_default=True)
@click.option("--ssh-backend", type=click.Choice(["native", "openssh"]), default="native", show_default=True)
@click.option("--cross-check", is_flag=True, help="Run native and openssl/ssh probes and flag disagreements.")
@click.option("--no-legacy", is_flag=True, help="Skip TLS 1.0/1.1 probes.")
@click.option(
    "--fail-on",
    type=click.Choice(["none", "classical", "at-risk"]),
    default="none",
    show_default=True,
    help="Exit 2 if any service is not PQ ready (classical) or is at risk at the configured Z (at-risk).",
)
@pass_ctx
def scan(
    c: Ctx,
    inventory: str,
    out: str | None,
    as_json: bool,
    timeout: float | None,
    concurrency: int | None,
    tls_backend: str,
    ssh_backend: str,
    cross_check: bool,
    no_legacy: bool,
    fail_on: str,
) -> None:
    """Probe every TLS and SSH service in INVENTORY with real post-quantum handshakes."""
    from aegisq.inventory import InventoryError, load_inventory
    from aegisq.netutil import Scope
    from aegisq.scanner.engine import ScanOptions, scan_all
    from aegisq.scanner.external import BackendUnavailable

    try:
        targets = load_inventory(inventory)
    except InventoryError as e:
        _fail(str(e))
    sc = c.cfg.scan
    opts = ScanOptions(
        timeout=timeout or sc.timeout,
        concurrency=concurrency or sc.concurrency,
        tls_backend=tls_backend,
        ssh_backend=ssh_backend,
        cross_check=cross_check,
        legacy_protocols=sc.legacy_protocols and not no_legacy,
        scope=Scope(sc.scope.allow, sc.scope.deny),
    )
    c.ws.audit.append(
        "scan.started",
        {"inventory": Path(inventory).name, "services": len(targets), "backend": f"{tls_backend}/{ssh_backend}"},
    )
    progress = None if as_json else (lambda r: click.echo(f"  scanned {r.service.name}: {r.status.value}", err=True))
    try:
        report = asyncio.run(scan_all(targets, opts, progress))
    except (BackendUnavailable, ValueError) as e:
        _fail(str(e))
    path = c.ws.save_scan(report)
    for r in report.results:
        c.ws.audit.append(
            "service.scanned",
            {
                "service": r.service.name,
                "endpoint": r.service.endpoint,
                "status": r.status.value,
                "errors": r.errors[:3],
            },
        )
    c.ws.audit.append("scan.completed", {"scan_id": report.scan_id, "summary": report.summary(), "file": path.name})
    if out:
        Path(out).write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _print_scan(report)
        click.echo(f"saved {path}")
    _gate(c, report.results, fail_on)


def _gate(c: Ctx, results: list[ServiceScan], fail_on: str) -> None:
    if fail_on == "none":
        return
    from aegisq.risk import rank

    if fail_on == "classical":
        bad = [r.service.name for r in results if r.status.scanned and r.status != Status.PQ_READY]
    else:
        bad = [r.service for r in rank(results, c.cfg.risk) if r.at_risk]
    if bad:
        click.secho(f"policy failure ({fail_on}): {', '.join(bad)}", fg="red", err=True)
        sys.exit(EXIT_POLICY)


def _load_scan(c: Ctx, scan_file: str | None) -> ScanReport:
    if scan_file:
        try:
            return ScanReport.model_validate_json(Path(scan_file).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            _fail(f"cannot read scan {scan_file}: {e}")
    rep = c.ws.latest_scan()
    if rep is None:
        _fail("no scan found: run `aegisq scan INVENTORY` first")
    return rep


# ----------------------------------------------------------------- cbom ---


@main.command()
@click.option("--scan", "scan_file", type=click.Path(exists=True, dir_okay=False), help="Scan JSON (default: latest).")
@click.option("--out", type=click.Path(dir_okay=False), default="cbom.json", show_default=True)
@click.option("--no-validate", is_flag=True, help="Skip schema validation (not recommended).")
@pass_ctx
def cbom(c: Ctx, scan_file: str | None, out: str, no_validate: bool) -> None:
    """Write a CycloneDX 1.6 Cryptographic Bill of Materials, validated against the official schema."""
    from aegisq.cbom import CBOMValidationError, build_cbom, validate_cbom

    report = _load_scan(c, scan_file)
    bom = build_cbom(report)
    valid = None
    if not no_validate:
        try:
            validate_cbom(bom)
            valid = True
        except CBOMValidationError as e:
            for err in e.errors[:20]:
                click.secho(f"  {err}", fg="red", err=True)
            _fail("generated CBOM failed CycloneDX 1.6 validation (not written)")
    Path(out).write_text(json.dumps(bom, indent=2), encoding="utf-8")
    c.ws.save_json("cbom.json", bom)
    c.ws.save_json(
        "cbom-summary.json",
        {
            "file": Path(out).name,
            "spec": "1.6",
            "components": len(bom["components"]),
            "valid": bool(valid),
            "serial": bom["serialNumber"],
        },
    )
    c.ws.audit.append(
        "cbom.generated",
        {
            "file": Path(out).name,
            "components": len(bom["components"]),
            "validated": bool(valid),
            "scan_id": report.scan_id,
        },
    )
    click.echo(
        f"wrote {out}: {len(bom['components'])} cryptographic assets"
        + (" (valid CycloneDX 1.6)" if valid else " (NOT validated)")
    )


@main.command("cbom-validate")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
def cbom_validate(file: str) -> None:
    """Validate any CycloneDX 1.6 JSON file against the bundled official schema."""
    from aegisq.cbom import CBOMValidationError, validate_cbom

    try:
        bom = json.loads(Path(file).read_text(encoding="utf-8"))
        validate_cbom(bom)
    except (OSError, json.JSONDecodeError) as e:
        _fail(f"cannot read {file}: {e}")
    except CBOMValidationError as e:
        for err in e.errors[:50]:
            click.secho(f"  {err}", fg="red", err=True)
        _fail(f"{file} is NOT valid CycloneDX 1.6", EXIT_POLICY)
    click.secho(f"{file} is valid CycloneDX 1.6", fg="green")


# ----------------------------------------------------------------- risk ---


@main.command()
@click.option("--scan", "scan_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--z", type=float, help="Years until a cryptographically relevant quantum computer.")
@click.option("--sweep", help="Comma-separated Z values, e.g. 5,10,15,20: show who stays at risk.")
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def risk(c: Ctx, scan_file: str | None, z: float | None, sweep: str | None, as_json: bool) -> None:
    """Rank services by Mosca margin X + Y - Z."""
    from aegisq.agent.tools import apply_facts
    from aegisq.risk import rank
    from aegisq.risk import sweep as do_sweep

    report = _load_scan(c, scan_file)
    scans = apply_facts(report.results, c.ws)
    ranking = rank(scans, c.cfg.risk, z)
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in ranking], indent=2))
        return
    zz = c.cfg.risk.z_years if z is None else z
    click.echo(f"Mosca ranking at Z = {zz} years (margin = X + Y - Z; positive = already at risk)\n")
    click.echo(f"{'#':>3} {'SERVICE':<24} {'STATUS':<12} {'DATA':<12} {'X':>5} {'Y':>5} {'MARGIN':>7}  SEVERITY")
    colors = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "white",
        "none": "green",
        "unknown": "bright_black",
    }
    for r in ranking:
        click.echo(
            f"{r.rank:>3} {r.service:<24} {r.status:<12} {r.data_category:<12} {r.x_retention:>5g} "
            f"{r.y_migration:>5g} {r.margin:>+7.1f}  " + click.style(r.severity, fg=colors[r.severity])
        )
    if sweep:
        try:
            zs = [float(x) for x in sweep.split(",") if x.strip()]
        except ValueError:
            _fail("--sweep must be comma-separated numbers")
        res = do_sweep(scans, c.cfg.risk, zs)
        click.echo("\nAt risk across assumptions (Z = " + ", ".join(f"{v:g}" for v in zs) + "):")
        for name, flags in res.items():
            click.echo(f"  {name:<24} " + " ".join(click.style("X", fg="red") if f else "." for f in flags))


# -------------------------------------------------------------- migrate ---


def _terminal_waiter(c: Ctx, approver: str) -> Any:
    def wait(a: Any) -> Any:
        click.echo("\n" + "=" * 72)
        click.secho(f"Approval requested for {a.service} (approval {a.id})", bold=True)
        for line in a.diff.splitlines():
            fg = (
                "green"
                if line.startswith("+") and not line.startswith("+++")
                else ("red" if line.startswith("-") and not line.startswith("---") else None)
            )
            click.secho(line, fg=fg)
        approve = click.confirm(f"{approver}, apply this change to {a.service}?", default=False)
        reason = click.prompt("Reason (optional)", default="", show_default=False)
        decided = c.ws.approvals.decide(a.id, approve, approver, reason or None)
        c.ws.audit.append(
            "approval.decided",
            {
                "approval_id": a.id,
                "service": a.service,
                "status": decided.status,
                "reason": reason or None,
                "via": "terminal",
            },
            actor=approver,
        )
        return decided

    return wait


@main.command()
@click.argument("inventory", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--planner",
    type=click.Choice(["auto", "gemma", "rules"]),
    default="auto",
    show_default=True,
    help="gemma = Gemma 4 chooses each tool call (Google's Gemini API with GEMINI_API_KEY, or Gemma 4 on this "
    "machine through Ollama); rules = deterministic, no AI; auto = gemma when one of those is available, else rules.",
)
@click.option("--service", "services", multiple=True, help="Limit to these services (repeatable).")
@click.option(
    "--approve-in",
    type=click.Choice(["dashboard", "terminal"]),
    default="dashboard",
    show_default=True,
    help="Where the human approves: the dashboard / `aegisq approve`, or a prompt in this terminal.",
)
@click.option("--approver", default=None, help="Name recorded for terminal approvals (default: OS user).")
@click.option(
    "--initiator",
    default=None,
    help="Who started this run (default: OS user). With separation of duties on, they cannot approve its changes.",
)
@click.option("--rescan/--no-rescan", default=True, show_default=True, help="Scan the inventory first.")
@pass_ctx
def migrate(
    c: Ctx,
    inventory: str,
    planner: str,
    services: tuple[str, ...],
    approve_in: str,
    approver: str | None,
    initiator: str | None,
    rescan: bool,
) -> None:
    """Run the migration agent: propose, get approval, apply, verify, roll back on failure."""
    from aegisq.agent.runner import choose_planner
    from aegisq.agent.tools import Toolbox
    from aegisq.inventory import InventoryError, load_inventory
    from aegisq.netutil import Scope
    from aegisq.scanner.engine import ScanOptions, scan_all

    try:
        targets = {t.name: t for t in load_inventory(inventory)}
    except InventoryError as e:
        _fail(str(e))
    unknown = [s for s in services if s not in targets]
    if unknown:
        _fail(f"unknown service(s): {', '.join(unknown)}")
    sc = c.cfg.scan
    if rescan:
        opts = ScanOptions(
            timeout=sc.timeout,
            concurrency=sc.concurrency,
            legacy_protocols=sc.legacy_protocols,
            scope=Scope(sc.scope.allow, sc.scope.deny),
        )
        report = asyncio.run(scan_all(list(targets.values()), opts))
        c.ws.save_scan(report)
        c.ws.audit.append(
            "scan.completed", {"scan_id": report.scan_id, "summary": report.summary(), "trigger": "migrate"}
        )
    else:
        report = _load_scan(c, None)
    # The inventory is authoritative for what may be touched and how.
    results = []
    for r in report.results:
        if r.service.name in targets:
            results.append(r.model_copy(update={"service": targets[r.service.name]}))
    report = report.model_copy(update={"results": results})

    initiator = (initiator or getpass.getuser()).strip()
    waiter = None
    if approve_in == "terminal":
        if c.cfg.agent.separation_of_duties:
            _fail(
                "separation of duties is on, so the person running the agent cannot approve its changes: "
                "approve on the dashboard as someone else, or set agent.separation_of_duties: false for a "
                "one-person setup"
            )
        if not sys.stdin.isatty():
            _fail("--approve-in terminal needs an interactive terminal")
        waiter = _terminal_waiter(c, approver or getpass.getuser())
    else:
        click.echo(
            "Approve or reject each change on the dashboard (`aegisq serve`) or with "
            "`aegisq approvals list` / `aegisq approve ID --by NAME`."
        )
    tb = Toolbox(c.ws, c.cfg, report, approval_waiter=waiter, initiator=initiator)
    try:
        agent = choose_planner(planner, c.cfg.agent)
    except RuntimeError as e:
        _fail(str(e))
    endpoint = getattr(agent, "endpoint", None)
    click.echo(f"planner: {agent.name}" + (f" ({endpoint.label})" if endpoint else ""))
    summary = agent.run(tb, list(services) or None)
    click.echo("\nOutcome:")
    for svc, outcome in summary.outcomes.items():
        color = {"fixed": "green", "rejected": "yellow", "skipped": "bright_black"}.get(outcome, "red")
        click.echo(f"  {svc:<24} " + click.style(outcome, fg=color))
        for note in summary.notes.get(svc, []):
            click.echo(f"      {note}")
    if summary.safety_rollbacks:
        click.secho(f"  safety net rolled back: {', '.join(summary.safety_rollbacks)}", fg="red")
    if summary.final_message and agent.name == "gemma":
        click.echo("\n" + summary.final_message)
    # Re-measure after the run, so the report's numbers are what the fleet looks like now.
    after = asyncio.run(
        scan_all(
            list(targets.values()),
            ScanOptions(
                timeout=sc.timeout,
                concurrency=sc.concurrency,
                legacy_protocols=sc.legacy_protocols,
                scope=Scope(sc.scope.allow, sc.scope.deny),
            ),
        )
    )
    c.ws.save_scan(after)
    c.ws.audit.append(
        "scan.completed", {"scan_id": after.scan_id, "summary": after.summary(), "trigger": "post-migration"}
    )
    from aegisq.report import generate_report

    paths = generate_report(c.ws, c.cfg)
    click.echo(f"\nreport: {paths[0]}")


# ------------------------------------------------------------ approvals ---


@main.group()
def approvals() -> None:
    """List and inspect approval requests."""


@approvals.command("list")
@click.option("--status", type=click.Choice(["pending", "approved", "rejected", "expired", "consumed", "cancelled"]))
@pass_ctx
def approvals_list(c: Ctx, status: str | None) -> None:
    rows = c.ws.approvals.list(status)
    if not rows:
        click.echo("no approvals")
    for a in rows:
        click.echo(
            f"{a.id}  {a.status:<9} {a.service:<20} {a.summary[:70]}" + (f"  [{a.decided_by}]" if a.decided_by else "")
        )


@approvals.command("show")
@click.argument("approval_id")
@pass_ctx
def approvals_show(c: Ctx, approval_id: str) -> None:
    a = c.ws.approvals.get(approval_id)
    if a is None:
        _fail(f"no approval {approval_id}")
    click.echo(json.dumps({k: v for k, v in a.to_dict().items() if k != "diff"}, indent=2))
    click.echo(a.diff)


def _decide(c: Ctx, approval_id: str, approve: bool, by: str, reason: str | None) -> None:
    try:
        a = c.ws.approvals.decide(approval_id, approve, by, reason)
    except (LookupError, PermissionError, ValueError) as e:
        _fail(str(e))
    c.ws.audit.append(
        "approval.decided",
        {"approval_id": a.id, "service": a.service, "status": a.status, "reason": reason, "via": "cli"},
        actor=by,
    )
    click.secho(f"{a.service}: {a.status} by {by}", fg="green" if approve else "yellow")


@main.command()
@click.argument("approval_id")
@click.option("--by", required=True, help="Your name (recorded in the audit log).")
@click.option("--reason", default=None)
@pass_ctx
def approve(c: Ctx, approval_id: str, by: str, reason: str | None) -> None:
    """Approve a pending change."""
    _decide(c, approval_id, True, by, reason)


@main.command()
@click.argument("approval_id")
@click.option("--by", required=True)
@click.option("--reason", required=True)
@pass_ctx
def reject(c: Ctx, approval_id: str, by: str, reason: str) -> None:
    """Reject a pending change."""
    _decide(c, approval_id, False, by, reason)


# ---------------------------------------------------------------- users ---


@main.group()
def users() -> None:
    """Manage dashboard users and roles (viewer, operator, approver, admin)."""


def _user_store(c: Ctx) -> Any:
    from aegisq.users import UserStore

    return UserStore(c.ws.home / "state.db")


def _read_password(stdin: bool) -> str:
    if stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return str(click.prompt("Password", hide_input=True, confirmation_prompt=True))


@users.command("add")
@click.argument("name")
@click.option("--role", type=click.Choice(["viewer", "operator", "approver", "admin"]), required=True)
@click.option("--password-stdin", is_flag=True, help="Read the password from standard input instead of prompting.")
@pass_ctx
def users_add(c: Ctx, name: str, role: str, password_stdin: bool) -> None:
    """Create a user who signs in with NAME and a password (at least 12 characters)."""
    try:
        _user_store(c).add(name, role, _read_password(password_stdin), created_by=f"cli:{getpass.getuser()}")
    except ValueError as e:
        _fail(str(e))
    c.ws.audit.append("user.created", {"name": name, "role": role, "via": "cli"}, actor=getpass.getuser())
    click.echo(f"{name} ({role}) can now sign in.")


@users.command("list")
@pass_ctx
def users_list(c: Ctx) -> None:
    """List users and their roles."""
    for u in _user_store(c).all():
        click.echo(f"{u.name:<24} {u.role:<9} {'' if u.has_password else 'no password: run `aegisq users password`'}")


@users.command("role")
@click.argument("name")
@click.argument("role", type=click.Choice(["viewer", "operator", "approver", "admin"]))
@pass_ctx
def users_role(c: Ctx, name: str, role: str) -> None:
    """Change a user's role."""
    store = _user_store(c)
    u = store.get(name)
    if u is not None and u.role == "admin" and role != "admin" and store.count_admins() == 1:
        _fail("at least one admin must remain")
    try:
        store.set_role(name, role)
    except (LookupError, ValueError) as e:
        _fail(str(e))
    c.ws.audit.append("user.role_changed", {"name": name, "role": role, "via": "cli"}, actor=getpass.getuser())
    click.echo(f"{name} is now {role}")


@users.command("password")
@click.argument("name")
@click.option("--password-stdin", is_flag=True, help="Read the password from standard input instead of prompting.")
@pass_ctx
def users_password(c: Ctx, name: str, password_stdin: bool) -> None:
    """Set a new password for a user. Signs them out everywhere."""
    try:
        _user_store(c).set_password(name, _read_password(password_stdin))
    except (LookupError, ValueError) as e:
        _fail(str(e))
    c.ws.audit.append("user.password_reset", {"name": name, "via": "cli"}, actor=getpass.getuser())
    click.echo(f"New password set for {name}.")


@users.command("remove")
@click.argument("name")
@pass_ctx
def users_remove(c: Ctx, name: str) -> None:
    """Remove a user. They are signed out at once."""
    store = _user_store(c)
    u = store.get(name)
    if u is not None and u.role == "admin" and store.count_admins() == 1:
        _fail("at least one admin must remain")
    try:
        store.remove(name)
    except LookupError as e:
        _fail(str(e))
    c.ws.audit.append("user.removed", {"name": name, "via": "cli"}, actor=getpass.getuser())
    click.echo(f"{name} removed")


# ---------------------------------------------------------------- audit ---


@main.group()
def audit() -> None:
    """Inspect the tamper-evident audit log."""


@audit.command("verify")
@pass_ctx
def audit_verify(c: Ctx) -> None:
    res = c.ws.audit.verify()
    if res.ok:
        click.secho(f"audit log intact: {res.entries} entries ({'HMAC' if res.keyed else 'SHA-256'} chain)", fg="green")
    else:
        _fail(f"audit log FAILED verification: {res.error}", EXIT_POLICY)


@audit.command("tail")
@click.option("-n", default=20, show_default=True)
@click.option("--event", default=None, help="Event prefix filter, e.g. patch.")
@pass_ctx
def audit_tail(c: Ctx, n: int, event: str | None) -> None:
    for e in c.ws.audit.tail(n, event):
        click.echo(
            f"{e['seq']:>5} {e['ts'][:19]} {e['actor']:<10} {e['event']:<28} "
            + json.dumps(e["data"], default=str)[:160]
        )


# --------------------------------------------------------------- report ---


@main.command()
@click.option("--z", type=float)
@pass_ctx
def report(c: Ctx, z: float | None) -> None:
    """Build the migration report (Markdown + HTML) from the audit log."""
    from aegisq.report import generate_report

    for p in generate_report(c.ws, c.cfg, z):
        click.echo(f"wrote {p}")


# ---------------------------------------------------------------- serve ---


@main.command()
@click.option("--host", default=None, help="Bind address (default from config: 127.0.0.1).")
@click.option("--port", type=int, default=None)
@click.option(
    "--inventory",
    type=click.Path(exists=True, dir_okay=False),
    help="The fleet the dashboard can rescan and migrate.",
)
@click.option("--read-only", is_flag=True, help="Show results only: no scans, migrations or other jobs from the web.")
@pass_ctx
def serve(c: Ctx, host: str | None, port: int | None, inventory: str | None, read_only: bool) -> None:
    """Run the dashboard: results, approvals, and buttons that run scans and migrations."""
    import uvicorn

    from aegisq.web.app import create_app

    try:
        app = create_app(
            c.cfg,
            inventory=os.path.abspath(inventory) if inventory else None,
            config_path=c.config_path,
            jobs_enabled=not read_only,
            background=True,
        )
    except ValueError as e:
        _fail(str(e))
    h, p = host or c.cfg.server.host, port or c.cfg.server.port
    click.echo(f"dashboard: http://{h}:{p}/")
    uvicorn.run(app, host=h, port=p, log_level="warning", server_header=False)


# ------------------------------------------------------------ benchmark ---


@main.command()
@click.argument("url")
@click.option("-n", default=1000, show_default=True, help="Handshakes per setting.")
@click.option("--method", type=click.Choice(["auto", "curl", "native"]), default="auto", show_default=True)
@click.option("--curl", "curl_bin", default="curl", show_default=True)
@pass_ctx
def benchmark(c: Ctx, url: str, n: int, method: str, curl_bin: str) -> None:
    """Measure handshake latency (p50/p99) and size: X25519MLKEM768 vs X25519."""
    from aegisq.benchmark import curl_supports_mlkem, run_benchmark

    if method == "curl" and not curl_supports_mlkem(curl_bin):
        _fail("this curl is not built with OpenSSL 3.5+; use --method native or the aegisq container image")
    try:
        res = run_benchmark(url, n, method, curl_bin)
    except (ValueError, OSError) as e:
        _fail(str(e))
    c.ws.save_json("benchmarks/latest.json", res)
    c.ws.audit.append("benchmark.completed", {"url": url, "method": res["method"], "results": res["results"]})
    for r in res["results"]:
        click.echo(f"{r['label']:<44} n={r['n']} p50={r['p50_ms']} ms p99={r['p99_ms']} ms failures={r['failures']}")
        if r.get("note"):
            click.secho(f"  {r['note']}", fg="red")
    s = res["sizes"]
    click.echo(
        f"key shares: client {s['client_key_share']}, server {s['server_key_share']}; "
        f"extra bytes/handshake: {s.get('extra_bytes_per_handshake')}"
    )
    click.echo(s["packet_split"])
    click.secho(res["caveat"], fg="yellow")


# --------------------------------------------------------------- claims ---

VERDICT_STYLE = {"confirmed": "green", "contradicted": "red", "unverifiable": "yellow"}


@main.group()
def claims() -> None:
    """Gemma 4 reads a config or screenshot; the scanner checks every claim it finds."""


@claims.command("check")
@click.option(
    "--text", "text_file", type=click.File("r", encoding="utf-8"), help="Config or command output (- = stdin)."
)
@click.option(
    "--image", "image_file", type=click.Path(exists=True, dir_okay=False), help="PNG, JPEG or WebP screenshot."
)
@click.option("--yes", is_flag=True, help="Scan every endpoint found, without asking one by one.")
@click.option("--no-scan", is_flag=True, help="Only show what Gemma read.")
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def claims_check(c: Ctx, text_file: Any, image_file: str | None, yes: bool, no_scan: bool, as_json: bool) -> None:
    """Extract endpoints and key-exchange claims with Gemma 4, then prove or disprove each with a handshake."""
    from aegisq.agent import claims as cl
    from aegisq.netutil import Scope
    from aegisq.scanner.engine import ScanOptions

    text = text_file.read() if text_file else None
    image = Path(image_file).read_bytes() if image_file else None
    try:
        post, ep = cl.gemma_client(c.cfg.agent, retries=3, timeout=180.0)
        click.echo(f"reading with {ep.label}", err=True)
        ext = cl.extract(post, ep.model, text=text, image=image, who=getpass.getuser())
    except (cl.ClaimError, RuntimeError) as e:
        _fail(str(e))
    cl.record_extraction(c.ws, ext)
    if not as_json:
        if not ext.endpoints:
            click.echo(f"no endpoints found. {ext.notes}".strip())
        for i, ep_claim in enumerate(ext.endpoints):
            mark = {True: "quoted from your text", False: "NOT found in your text", None: "from the image"}[
                ep_claim.grounded
            ]
            click.echo(f"[{i}] {ep_claim.label:<34} {cl.claim_text(ep_claim)}")
            click.echo(f"    evidence ({mark}): {ep_claim.evidence[:120]}")
        for d in ext.dropped:
            click.secho(f"    ignored: {d}", fg="yellow")
    picked: list[int] = []
    if not no_scan and ext.endpoints:
        if yes:
            picked = [i for i, x in enumerate(ext.endpoints) if x.grounded is not False]
            for x in ext.endpoints:
                if x.grounded is False:
                    click.secho(f"    not scanning {x.label}: not found in your text", fg="yellow")
        else:
            picked = [i for i, x in enumerate(ext.endpoints) if click.confirm(f"scan {x.label}?", default=False)]
    if picked:
        sc = c.cfg.scan
        opts = ScanOptions(
            timeout=sc.timeout,
            concurrency=sc.concurrency,
            legacy_protocols=False,
            scope=Scope(sc.scope.allow, sc.scope.deny),
        )
        try:
            cl.verify(c.ws, ext, picked, opts, getpass.getuser())
        except (cl.ClaimError, ValueError) as e:
            _fail(str(e))
    if as_json:
        click.echo(ext.model_dump_json(indent=2))
        return
    for row in ext.checks or []:
        click.echo(
            f"{row['endpoint']:<34} "
            + click.style(f"{row['verdict'].upper():<13}", fg=VERDICT_STYLE[row["verdict"]])
            + f" claim: {row['claim']}; server: {row['observed']}"
        )
        if row.get("fix"):
            click.echo(f"    fix: {row['fix']}")
    click.echo(f"saved {c.ws.home / 'claims' / (ext.id + '.json')}")
    if ext.scan_file:
        click.echo(f"CBOM for this check: aegisq cbom --scan {c.ws.home / ext.scan_file}")


@main.command("gemma-check")
@click.option(
    "--api",
    type=click.Choice(["configured", "native", "openai", "both"]),
    default="configured",
    show_default=True,
    help="Gemini API only: test the native generateContent method, the OpenAI-compatible one, or both.",
)
@pass_ctx
def gemma_check(c: Ctx, api: str) -> None:
    """Send three real requests to Gemma 4 (tool call, image, claim extraction) and report each."""
    import dataclasses

    from aegisq.agent.gemma_check import run_checks
    from aegisq.agent.runner import GemmaPlanner, resolve_local_endpoint

    try:
        base = resolve_local_endpoint(c.cfg.agent)
    except RuntimeError as e:
        _fail(str(e))
    apis = [base.api] if api == "configured" else ["native", "openai"] if api == "both" else [api]
    google = "generativelanguage.googleapis.com" in base.base_url
    if not google and apis != ["openai"]:
        _fail("--api native and --api both need the Gemini API (GEMINI_API_KEY)")
    runs: list[dict[str, Any]] = []
    for a in apis:
        ep = dataclasses.replace(base, api=a)
        click.echo(f"checking {ep.label}")
        results = run_checks(GemmaPlanner(ep, retries=2, timeout=180.0)._http_post, ep.model)
        for r in results:
            mark = click.style("pass", fg="green") if r["ok"] else click.style("FAIL", fg="red")
            click.echo(f"{mark}  {r['check']:<18} {r['seconds']:>6.1f}s  {r['detail']}")
        runs.append({"model": ep.model, "endpoint": ep.base_url, "api": a, "results": results})
        c.ws.audit.append("gemma.checked", runs[-1])
    best = next((r for r in runs if all(x["ok"] for x in r["results"])), runs[0])
    c.ws.save_json("gemma-check.json", {**best, "runs": runs})
    if not all(x["ok"] for x in best["results"]):
        sys.exit(1)
    if len(runs) > 1 or best["api"] != base.api:
        click.echo(f"use it: AEGISQ_LLM_API={best['api']}")


@main.command("brief")
@click.argument("service")
@click.option("--template", is_flag=True, help="Do not use Gemma 4: list the facts as the brief.")
@click.option("--json", "as_json", is_flag=True, help="Print the brief as JSON.")
@click.option("-o", "--out", type=click.Path(dir_okay=False, writable=True), help="Also write the Markdown here.")
@pass_ctx
def brief_cmd(c: Ctx, service: str, template: bool, as_json: bool, out: str | None) -> None:
    """Write a fact-checked brief for the team that owns SERVICE (from the latest scan)."""
    from aegisq.agent import brief
    from aegisq.agent.claims import gemma_client
    from aegisq.agent.tools import apply_facts

    report = c.ws.latest_scan()
    if report is None:
        _fail("no scan yet: run `aegisq scan` first")
    scan = next((s for s in apply_facts(report.results, c.ws) if s.service.name == service), None)
    if scan is None:
        _fail(f"no service named {service!r} in the latest scan")
    post = model = None
    from aegisq.agent.runner import gemma_status

    ready, why = (False, "") if template else gemma_status(c.cfg.agent)
    if not template and not ready:
        click.secho(f"Gemma 4 is not set up ({why}); using the template", fg="yellow", err=True)
    if ready:
        try:
            post, ep = gemma_client(c.cfg.agent, retries=3, timeout=180.0)
            model = ep.model
            click.echo(f"writing with {ep.label}", err=True)
        except RuntimeError as e:
            click.secho(f"Gemma 4 is not set up ({e}); using the template", fg="yellow", err=True)
    b = brief.write(c.ws, scan, c.cfg.risk, post, model, who=getpass.getuser())
    md = b.markdown()
    if out:
        Path(out).write_text(md)
    if as_json:
        click.echo(json.dumps(b.to_dict(), indent=2))
    else:
        click.echo(md)
        if b.removed:
            click.secho(f"{len(b.removed)} sentence(s) removed by the fact check", fg="yellow", err=True)


@main.command("redteam")
@click.option(
    "--planner",
    type=click.Choice(["scripted", "gemma"]),
    default="scripted",
    show_default=True,
    help="scripted: a model that obeys a prompt injection. gemma: the real Gemma 4 planner.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the full result as JSON.")
@pass_ctx
def redteam_cmd(c: Ctx, planner: str, as_json: bool) -> None:
    """Attack a throwaway sandbox fleet and check, in code, that every unsafe action was refused."""
    from aegisq.agent import redteam
    from aegisq.agent.runner import resolve_local_endpoint

    ep = None
    if planner == "gemma":
        try:
            ep = resolve_local_endpoint(c.cfg.agent)
        except RuntimeError as e:
            _fail(str(e))
        click.echo(f"red-teaming {ep.label} in a temporary sandbox", err=True)
    result = redteam.run(planner, ep)
    c.ws.save_json("redteam.json", result)
    c.ws.audit.append(
        "redteam.finished",
        {k: result[k] for k in ("planner", "model", "tool_calls", "invariants", "passed")},
    )
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        for r in result["attacks"]:
            mark = click.style("refused", fg="green") if r["refused"] else click.style("ALLOWED", fg="red")
            click.echo(f"{mark}  {r['attack']:<42} {r['detail']}")
        click.echo("")
        for name, ok in result["invariants"].items():
            click.echo(f"{click.style('pass', fg='green') if ok else click.style('FAIL', fg='red')}  {name}")
        click.echo(f"{result['tool_calls']} tool calls; saved {c.ws.home / 'redteam.json'}")
    if not result["passed"]:
        sys.exit(1)


# --------------------------------------------------------------- doctor ---


@main.command()
@pass_ctx
def doctor(c: Ctx) -> None:
    """Check the local environment and optional components."""
    from aegisq.scanner.external import openssl_version, ssh_supported_kex

    def line(ok: bool | None, name: str, detail: str) -> None:
        mark = {
            True: click.style("ok  ", fg="green"),
            False: click.style("no  ", fg="red"),
            None: click.style("--  ", fg="yellow"),
        }[ok]
        click.echo(f"{mark}{name:<28} {detail}")

    line(
        True if c.env_file else None,
        ".env file",
        f"{c.env_file[0]} ({c.env_file[1]} variables loaded)" if c.env_file else "none (looked for .env and demo/.env)",
    )
    ov = openssl_version()
    line(True, "native TLS/SSH probes", "built in (no OpenSSL 3.5 needed)")
    line(
        True if ov and ov >= (3, 5, 0) else None,
        "openssl backend",
        f"OpenSSL {'.'.join(map(str, ov))}"
        + ("" if ov >= (3, 5, 0) else ": optional, needs 3.5+ (the built-in TLS probe is used)")
        if ov
        else "optional: openssl not found (the built-in TLS probe is used)",
    )
    kex = ssh_supported_kex()
    line(
        True if "mlkem768x25519-sha256" in kex else None,
        "openssh backend",
        "mlkem768x25519 available"
        if "mlkem768x25519-sha256" in kex
        else "optional: local ssh missing or < 9.9 (the built-in SSH probe is used)",
    )
    from aegisq.benchmark import curl_supports_mlkem

    line(
        curl_supports_mlkem() or None,
        "curl benchmark",
        "curl with OpenSSL 3.5+" if curl_supports_mlkem() else "use --method native or the container",
    )
    from aegisq.agent.runner import gemma_status

    ok, detail = gemma_status(c.cfg.agent)
    line(ok or None, "Gemma 4 planner", detail)
    last = c.ws.load_json("gemma-check.json")
    if last:
        passed = sum(1 for r in last["results"] if r["ok"])
        line(
            passed == len(last["results"]),
            "Gemma 4 live check",
            f"{passed}/{len(last['results'])} passed on {last['model']} ({last.get('api', 'openai')} API)",
        )
    else:
        line(None, "Gemma 4 live check", "not run yet: `aegisq gemma-check`")
    line(bool(shutil.which("git")) or None, "git (patch branches)", shutil.which("git") or "not found")
    line(bool(shutil.which("docker")) or None, "docker (demo fleet)", shutil.which("docker") or "not found")
    n_users = _user_store(c).count()
    line(
        bool(n_users) or None,
        "dashboard users",
        f"{n_users} can sign in" if n_users else "none yet: open the dashboard on this computer or `aegisq users add`",
    )
    line(
        bool(os.environ.get("AEGISQ_AUDIT_KEY")) or None,
        "audit HMAC key",
        "set" if os.environ.get("AEGISQ_AUDIT_KEY") else "not set: SHA-256 chain (set AEGISQ_AUDIT_KEY for HMAC)",
    )
    res = c.ws.audit.verify()
    line(res.ok, "audit log", f"{res.entries} entries" if res.ok else str(res.error))
    from aegisq.cbom import _validator

    try:
        _validator()
        line(True, "CycloneDX 1.6 schema", "bundled and loadable")
    except Exception as e:
        line(False, "CycloneDX 1.6 schema", str(e))


if __name__ == "__main__":  # pragma: no cover
    main()
