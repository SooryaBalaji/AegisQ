import { api } from "../api.js";
import { Empty, PageHead, Pill, ago, when } from "../ui.jsx";
import { ApprovalCard } from "./Run.jsx";

const STATE = {
  consumed: ["Applied", "safe"],
  approved: ["Approved", "safe"],
  rejected: ["Rejected", "risk"],
  expired: ["Expired", "idle"],
  cancelled: ["Withdrawn", "idle"],
};

export default function Approvals({ me, perms, approvals, loadApprovals, guard, toast }) {
  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending").slice(0, 50);

  const decide = (a, approve) => guard(async () => {
    let reason = null;
    if (!approve) {
      reason = window.prompt("Why are you rejecting it? This goes in the audit log.");
      if (reason === null) return;
    }
    await api(`/api/approvals/${encodeURIComponent(a.id)}/decision`, { method: "POST", body: { approve, reason } });
    toast(approve ? `Approved the change to ${a.service}` : `Rejected the change to ${a.service}`);
    loadApprovals();
  });

  return (
    <>
      <PageHead title="Approvals">
        Every change the agent proposes waits here for a person. Approvals are tied to the exact change shown and expire after
        an hour.
      </PageHead>
      <section className="panel">
        <div className="panel-head">
          <div><h2>Waiting</h2><p>{pending.length ? `${pending.length} waiting for a decision` : "Nothing is waiting"}</p></div>
        </div>
        {pending.length ? (
          pending.map((a) => (
            <div key={a.id}>
              <ApprovalCard a={a} me={me} perms={perms} onDecide={decide} />
              <p className="hint approval-meta">
                Requested {ago(a.requested_at)}{a.initiated_by ? ` in a run started by ${a.initiated_by}` : ""}. Expires {when(a.expires_at)}.
              </p>
            </div>
          ))
        ) : (
          <Empty title="Nothing to approve">Changes appear here while a Scan and fix run is going.</Empty>
        )}
      </section>

      <section className="panel">
        <div className="panel-head"><div><h2>History</h2></div></div>
        {decided.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Decided</th><th>Server</th><th>Change</th><th>Result</th><th>Started by</th><th>Decided by</th></tr></thead>
              <tbody>
                {decided.map((a) => {
                  const [label, t] = STATE[a.status] || [a.status, "idle"];
                  return (
                    <tr key={a.id}>
                      <td className="nowrap">{when(a.decided_at || a.requested_at)}</td>
                      <td><b>{a.service}</b></td>
                      <td className="wrap ink2">{a.summary}{a.reason ? <div className="sub">Reason: {a.reason}</div> : null}</td>
                      <td><Pill tone={t}>{label}</Pill></td>
                      <td>{a.initiated_by || <span className="muted">Unknown</span>}</td>
                      <td>{a.decided_by || <span className="muted">Nobody</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No decisions yet" />
        )}
      </section>
    </>
  );
}
