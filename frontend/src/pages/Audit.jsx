import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Empty, PageHead, when } from "../ui.jsx";

const FILTERS = [
  ["", "Everything"],
  ["patch.", "Changes"],
  ["approval.", "Approvals"],
  ["service.", "Verification"],
  ["agent.", "Agent"],
  ["scan.", "Scans"],
  ["claims.", "Claim checks"],
  ["brief.", "Owner briefs"],
  ["redteam.", "Red team"],
  ["user.", "People and sign-ins"],
  ["alert.", "Alerts"],
];

const SENTENCE = {
  "scan.started": (d) => `Scan started${d.services ? ` for ${d.services} servers` : ""}`,
  "service.scanned": (d) => `Scanned ${d.service || d.name || "a server"}${d.status ? `: ${d.status.replace(/_/g, " ")}` : ""}`,
  "report.generated": () => "Wrote the migration report",
  "scan.completed": (d) => `Scan finished: ${d.summary?.pq_ready ?? "?"} of ${d.summary?.total ?? "?"} post-quantum`,
  "job.started": (d) => `Started: ${d.label}`,
  "job.finished": (d) => `Job ${d.status}${d.exit_code != null && d.exit_code !== 0 ? ` (exit ${d.exit_code})` : ""}`,
  "patch.proposed": (d) => `Proposed a change to ${d.service}`,
  "patch.rejected_by_guardrail": (d) => `Guardrail refused a change to ${d.service}: ${d.reason}`,
  "patch.applying": (d) => `Applying the change to ${d.service}`,
  "patch.applied": (d) => `Applied the change to ${d.service}; config test passed`,
  "patch.test_failed": (d) => `Config test failed on ${d.service}; old config restored`,
  "patch.reload_failed": (d) => `Reload failed on ${d.service}; old config restored`,
  "patch.rolled_back": (d) => `Rolled back ${d.service}: ${d.reason}`,
  "patch.refused_drift": (d) => `Refused: ${d.service} changed since the proposal`,
  "patch.refused_no_approval": (d) => `Refused: no valid approval for ${d.service}`,
  "patch.refused_server_version": (d) => `Refused: ${d.service} needs a newer server version`,
  "service.verified": (d) => `Verified ${d.service}: ${d.pq_detail}`,
  "service.verify_failed": (d) => `Verification failed on ${d.service}`,
  "approval.requested": (d) => `Asked for approval: ${d.service}`,
  "approval.decided": (d) => `${d.status === "approved" ? "Approved" : "Rejected"} the change to ${d.service}`,
  "approval.outcome": (d) => `Approval for ${d.service}: ${d.status}`,
  "approval.cancelled": (d) => `Withdrew the approval request for ${d.service}`,
  "agent.started": (d) => `Agent started (${d.planner}${d.model ? `, ${d.model}` : ""})`,
  "agent.finished": () => "Agent finished",
  "agent.tool_call": (d) => `Agent called ${d.tool}${d.is_error ? " (refused)" : ""}`,
  "agent.safety_rollback": (d) => `Safety net rolled back ${(d.services || []).join(", ")}`,
  "tls_library.checked": (d) => `Checked the TLS library of ${d.service}: ${d.detail}`,
  "config.read": (d) => `Read the config of ${d.service}`,
  "user.signed_in": () => "Signed in",
  "user.sign_in_failed": (d) => `Failed sign-in as ${d.name}`,
  "user.created": (d) => `Added ${d.name} as ${d.role}`,
  "user.role_changed": (d) => `Made ${d.name} ${d.role}`,
  "user.password_reset": (d) => `Set a new password for ${d.name}`,
  "user.password_changed": () => "Changed their password",
  "user.removed": (d) => `Removed ${d.name}`,
  "alert.sent": (d) => `Sent a ${d.event} alert`,
  "alert.failed": (d) => `Could not send a ${d.event} alert: ${d.status}`,
  "claims.extracted": (d) => `Gemma 4 (${d.model}) read ${d.endpoints?.length ?? 0} servers from ${d.source === "image" ? "a screenshot" : d.source === "text" ? "pasted text" : "text and a screenshot"}${d.ungrounded?.length ? `; ${d.ungrounded.length} not quoted from the text` : ""}`,
  "claims.verified": (d) => `Tested the claims: ${d.summary?.confirmed ?? 0} confirmed, ${d.summary?.contradicted ?? 0} contradicted, ${d.summary?.unverifiable ?? 0} unverifiable`,
  "gemma.checked": (d) => `Live Gemma 4 check on ${d.model} (${d.api || "openai"} API): ${(d.results || []).filter((r) => r.ok).length} of ${(d.results || []).length} passed`,
  "benchmark.completed": (d) => `Measured handshakes on ${d.url}`,
  "brief.generated": (d) => `Wrote the owner brief for ${d.service}: ${d.kept} kept, ${d.removed} removed by the fact check`,
  "redteam.finished": (d) => `Red team (${d.planner}${d.model ? `, ${d.model}` : ""}): ${d.passed ? "every attack refused" : "FAILED"}`,
};

export default function Audit({ chain, guard }) {
  const [filter, setFilter] = useState("");
  const [rows, setRows] = useState(null);
  const [open, setOpen] = useState(null);

  useEffect(() => {
    let live = true;
    const load = () => guard(async () => {
      const r = await api(`/api/audit?limit=300${filter ? `&event=${encodeURIComponent(filter)}` : ""}`);
      if (live) setRows((r || []).slice().reverse());
    });
    load();
    const t = setInterval(load, 5000);
    return () => { live = false; clearInterval(t); };
  }, [filter]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <PageHead title="Audit log">
        Every scan, proposal, decision, change and sign-in. Each event carries the hash of the one before it, so an edited or
        deleted line breaks the chain.
      </PageHead>
      {chain && (
        <div className={`notice ${chain.ok ? "" : "risk"}`}>
          <span className={`dot ${chain.ok ? "safe" : "risk"}`} aria-hidden="true" />
          <span>
            {chain.ok
              ? `The chain is intact: all ${chain.entries} events verify (${chain.keyed ? "HMAC with AEGISQ_AUDIT_KEY" : "SHA-256"}).`
              : `The chain is broken: ${chain.error}. Someone or something changed the log file.`}
          </span>
        </div>
      )}
      <section className="panel mt16">
        <div className="toolbar">
          <label className="row">
            <span className="muted">Show</span>
            <select className="select auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
              {FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <span className="muted">{rows ? `Latest ${rows.length} events` : ""}</span>
        </div>
        {rows && rows.length === 0 && <Empty title="No events" />}
        {rows && rows.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th className="num">#</th><th>Time</th><th>Who</th><th>What happened</th></tr></thead>
              <tbody>
                {rows.map((e) => {
                  const say = SENTENCE[e.event];
                  let text = e.event;
                  try { if (say) text = say(e.data || {}); } catch { /* keep the event name */ }
                  return (
                    <tr key={e.seq} className="click" tabIndex={0} onClick={() => setOpen(open === e.seq ? null : e.seq)}
                      onKeyDown={(k) => k.key === "Enter" && setOpen(open === e.seq ? null : e.seq)} aria-expanded={open === e.seq}>
                      <td className="num muted">{e.seq}</td>
                      <td className="nowrap">{when(e.ts)}</td>
                      <td>{e.actor}</td>
                      <td className="wrap">
                        {text}
                        {open === e.seq && <pre className="event-data">{JSON.stringify(e.data, null, 2)}</pre>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
