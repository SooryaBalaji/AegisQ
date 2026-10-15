function Diff({ text }) {
  return (
    <div className="diff" role="region" aria-label="Proposed diff">
      {text.split("\n").map((line, i) => {
        const cls = line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "";
        return <span key={i} className={cls}>{line + "\n"}</span>;
      })}
    </div>
  );
}

const DECISION = { consumed: "approved · applied", approved: "approved", rejected: "rejected", expired: "expired", cancelled: "cancelled", pending: "pending" };

export default function Approvals({ client, approvals, reload, me }) {
  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending").slice(0, 30);
  const canApprove = (me.permissions || []).includes("approve");

  const decide = async (id, approve) => {
    let reason = null;
    if (!approve) {
      reason = prompt("Reason for rejecting (recorded in the audit log):");
      if (reason === null) return;
    } else if (!confirm("Apply this change? It will be tested, reloaded and verified, and rolled back automatically on failure.")) {
      return;
    }
    try {
      await client.api(`/api/approvals/${encodeURIComponent(id)}/decision`, { method: "POST", body: JSON.stringify({ approve, reason }) });
    } catch (e) { alert(`Decision failed: ${e.message}`); }
    reload();
  };

  return (
    <section className="card" id="approvals" aria-labelledby="appr-title">
      <h2 id="appr-title">Approvals <span className="muted">every change needs a named human</span></h2>
      {!canApprove && <p className="warn-banner">Your role ({me.role}) can see proposed changes but not approve them.</p>}
      {pending.length === 0 ? <p className="muted">Nothing waiting for approval.</p> : pending.map((a) => {
        const own = a.require_other && a.initiated_by && a.initiated_by.toLowerCase() === me.identity.toLowerCase();
        return (
          <div className="pending-item" key={a.id}>
            <div className="row-between">
              <strong>{a.service}</strong>
              <span className="muted small mono">{`approval ${a.id} · expires ${new Date(a.expires_at * 1000).toLocaleTimeString()}`}</span>
            </div>
            {a.initiated_by && <p className="muted small">{`Run started by ${a.initiated_by}${a.require_other ? " · someone else must approve" : ""}`}</p>}
            <Diff text={a.diff} />
            {canApprove && (
              <div className="btns">
                <button type="button" disabled={own} title={own ? "You started this run, so another approver must decide" : ""} onClick={() => decide(a.id, true)}>Approve</button>
                <button type="button" className="danger" onClick={() => decide(a.id, false)}>Reject</button>
              </div>
            )}
            {own && <p className="muted small">You started this run, so another approver must approve it (separation of duties). You can still reject it.</p>}
          </div>
        );
      })}
      <details>
        <summary className="muted">Recent decisions</summary>
        <div className="scroll">
          <table className="data">
            <thead><tr><th>When</th><th>Service</th><th>Status</th><th>Started by</th><th>Decided by</th><th>Change</th></tr></thead>
            <tbody>{decided.map((a) => (
              <tr key={a.id}>
                <td className="small">{new Date((a.decided_at || a.requested_at) * 1000).toLocaleString()}</td>
                <td>{a.service}</td><td>{DECISION[a.status] || a.status}</td><td>{a.initiated_by || "–"}</td><td>{a.decided_by || "–"}</td><td className="mono small">{a.summary}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
