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

export default function Approvals({ client, approvals, reload }) {
  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending").slice(0, 30);

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
      <h2 id="appr-title">Approvals <span className="muted small">every change needs a named human</span></h2>
      {pending.length === 0 ? <p className="muted">Nothing waiting for approval.</p> : pending.map((a) => (
        <div className="pending-item" key={a.id}>
          <div className="row-between">
            <strong>{a.service}</strong>
            <span className="muted small mono">{`approval ${a.id} · expires ${new Date(a.expires_at * 1000).toLocaleTimeString()}`}</span>
          </div>
          <Diff text={a.diff} />
          <div className="btns">
            <button type="button" onClick={() => decide(a.id, true)}>Approve</button>
            <button type="button" className="danger" onClick={() => decide(a.id, false)}>Reject</button>
          </div>
        </div>
      ))}
      <details>
        <summary className="muted">Recent decisions</summary>
        <div className="scroll">
          <table className="data">
            <thead><tr><th>When</th><th>Service</th><th>Status</th><th>By</th><th>Change</th></tr></thead>
            <tbody>{decided.map((a) => (
              <tr key={a.id}>
                <td className="small">{new Date((a.decided_at || a.requested_at) * 1000).toLocaleString()}</td>
                <td>{a.service}</td><td>{a.status}</td><td>{a.decided_by || "–"}</td><td className="mono small">{a.summary}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
