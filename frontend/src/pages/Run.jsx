import { useEffect, useRef, useState } from "react";
import { AuthError, api, followJob, sleep } from "../api.js";
import FleetMap from "../FleetMap.jsx";
import { Diff, Empty, PageHead, Panel, Pill, Status, plural } from "../ui.jsx";

const SCANNED = /^\s*scanned (.+): ([a-z0-9_]+)\s*$/;
const STEPS = ["Scan servers", "Check exposure", "Fix and verify", "Seal the audit log"];
const OUTCOME = {
  fixed: ["Fixed", "safe"],
  rejected: ["Rejected", "idle"],
  skipped: ["Skipped", "idle"],
  failed: ["Not fixed", "risk"],
  rolled_back: ["Rolled back", "warn"],
};

function Check() {
  return <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 5.2l2 2 4-4.4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

export default function Run({ me, perms, guard, toast, loadOverview, loadApprovals, loadChain }) {
  const [caps, setCaps] = useState(null);
  const [target, setTarget] = useState("inventory");
  const [hosts, setHosts] = useState("");
  const [action, setAction] = useState("scan");
  const [planner, setPlanner] = useState("rules");
  const [error, setError] = useState("");

  const [run, setRun] = useState(null); // {phase, state[], notes[], nodes[], log[], pending[], result}
  const alive = useRef(true);
  const job = useRef(null);
  useEffect(() => () => { alive.current = false; }, []);

  useEffect(() => {
    guard(async () => {
      const c = await api("/api/capabilities");
      setCaps(c);
      if (!c.inventory) setTarget("custom");
      if (c.planners?.gemma?.ok) setPlanner("gemma");
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (!caps) return <PageHead title="Run" />;
  const managed = caps.services.filter((s) => s.managed);
  const canFix = caps.inventory && managed.length > 0 && target === "inventory";
  const canStart = caps.jobs && perms.has("run");
  const running = run && !run.result;

  const patch = (fn) => setRun((r) => (r ? { ...r, ...fn(r) } : r));
  const step = (i, st, note) => patch((r) => {
    const state = r.state.slice(); const notes = r.notes.slice();
    state[i] = st; if (note !== undefined) notes[i] = note;
    return { phase: i, state, notes };
  });
  const lines = (ls) => patch((r) => {
    let nodes = r.nodes;
    for (const l of ls) {
      const m = SCANNED.exec(l);
      if (!m) continue;
      nodes = nodes.slice();
      let k = nodes.findIndex((n) => n.name === m[1]);
      if (k < 0) k = nodes.findIndex((n) => !n.name);
      if (k < 0) nodes.push({ name: m[1], status: m[2] }); else nodes[k] = { name: m[1], status: m[2] };
    }
    return { nodes, log: [...r.log, ...ls].slice(-600), focus: nodes === r.nodes ? r.focus : null };
  });

  const start = async () => {
    const list = target === "custom" ? hosts.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")) : [];
    if (target === "custom" && !list.length) { setError("Enter at least one server."); return; }
    setError("");
    const fix = action === "fix" && canFix;
    const t0 = Date.now();
    setRun({
      phase: 0, state: ["active", "waiting", fix ? "waiting" : "skipped", "waiting"], notes: [],
      nodes: target === "inventory" ? caps.services.map((s) => ({ name: s.name, status: null })) : list.map(() => ({ name: null, status: null })),
      log: [], pending: [], result: null, fix,
    });
    const result = { started: t0, fix };
    try {
      const last = await api("/api/audit?limit=1");
      const seq0 = last?.length ? Math.max(...last.map((e) => e.seq)) : -1;

      const sj = await api("/api/jobs", { method: "POST", body: target === "custom" ? { kind: "scan", targets: list.join("\n") } : { kind: "scan" } });
      job.current = sj.id;
      const scan = await followJob(sj.id, lines, () => alive.current);
      job.current = null;
      if (scan.status !== "succeeded") throw new Error(scan.status === "cancelled" ? "The scan was cancelled." : "The scan failed. See the log for details.");
      step(0, "done", `${plural(scan.lines.filter((l) => SCANNED.test(l)).length, "server")} scanned`);

      step(1, "active");
      const ov = await api("/api/overview");
      await loadOverview();
      const sum = ov?.scan?.summary;
      if (ov && target === "inventory") patch((r) => ({ nodes: r.nodes.map((n) => ({ ...n, status: ov.services.find((x) => x.name === n.name)?.status || n.status })) }));
      step(1, "done", sum ? `${sum.pq_ready} of ${sum.total} use post-quantum key exchange; ${ov.services.filter((s) => s.at_risk).length} exposed` : "No results");
      result.before = Object.fromEntries((ov?.services || []).map((s) => [s.name, s.status]));

      if (fix) {
        step(2, "active", planner === "gemma" ? "Gemma 4 is planning the changes" : "The rules planner is planning the changes");
        const mj = await api("/api/jobs", { method: "POST", body: { kind: "migrate", planner, services: [] } });
        job.current = mj.id;
        let polling = true;
        (async () => {
          while (polling && alive.current) {
            try {
              const p = (await api("/api/approvals?status=pending")) || [];
              patch(() => ({ pending: p.filter((a) => a.requested_at * 1000 >= t0 - 5000) }));
            } catch { /* next tick */ }
            await sleep(1200);
          }
        })();
        const mig = await followJob(mj.id, lines, () => alive.current);
        polling = false;
        job.current = null;
        const [ov2, appr, tail] = await Promise.all([api("/api/overview"), api("/api/approvals"), api("/api/audit?limit=200&event=agent.")]);
        const fin = (tail || []).filter((e) => e.event === "agent.finished" && e.seq > seq0).pop();
        result.outcomes = fin ? fin.data.outcomes : {};
        result.notes = fin?.data?.final_message || "";
        result.approvals = (appr || []).filter((a) => a.requested_at * 1000 >= t0 - 5000);
        result.after = Object.fromEntries((ov2?.services || []).map((s) => [s.name, s.status]));
        const fixed = Object.values(result.outcomes).filter((o) => o === "fixed").length;
        patch(() => ({ pending: [] }));
        step(2, mig.status === "succeeded" ? "done" : "failed", `${plural(fixed, "server")} fixed`);
        await loadOverview();
        loadApprovals();
      }

      step(3, "active");
      const ver = await api("/api/audit/verify");
      loadChain();
      step(3, ver.ok ? "done" : "failed", ver.ok ? `Verified, ${ver.entries} events in the chain` : `Verification failed: ${ver.error}`);
      result.finished = Date.now();
      patch(() => ({ result }));
    } catch (e) {
      if (e instanceof AuthError) { guard(() => { throw e; }); return; }
      patch((r) => {
        const state = r.state.map((s) => (s === "active" ? "failed" : s));
        return { state, result: { ...result, error: e.message, finished: Date.now() } };
      });
    }
  };

  const decide = (a, approve) => guard(async () => {
    await api(`/api/approvals/${encodeURIComponent(a.id)}/decision`, { method: "POST", body: { approve, reason: approve ? null : "Rejected from Run" } });
    patch((r) => ({ pending: r.pending.filter((x) => x.id !== a.id) }));
    toast(approve ? `Approved the change to ${a.service}` : `Rejected the change to ${a.service}`);
  });
  const cancel = () => guard(async () => {
    if (job.current) await api(`/api/jobs/${encodeURIComponent(job.current)}/cancel`, { method: "POST" });
    toast("Cancelling. Anything applied but not verified is rolled back.");
  });

  return (
    <>
      <PageHead title="Run">Scan servers, then let the agent propose fixes for the ones AegisQ manages. Every change waits for a person to approve it.</PageHead>
      <div className="grid-run">
        <Panel title="New run">
          <div className="form">
            <fieldset className="choice" disabled={running}>
              <legend className="field"><span>Servers</span></legend>
              <label className="choice-item">
                <input type="radio" name="target" checked={target === "inventory"} disabled={!caps.inventory} onChange={() => setTarget("inventory")} />
                <span><b>Inventory</b><small>{caps.inventory ? `${plural(caps.services.length, "server")}, ${managed.length} managed by AegisQ` : "Start AegisQ with --inventory to use one"}</small></span>
              </label>
              <label className="choice-item">
                <input type="radio" name="target" checked={target === "custom"} onChange={() => { setTarget("custom"); setAction("scan"); }} />
                <span><b>Other servers</b><small>Scan only. One per line: host, host:port, or host:port ssh</small></span>
              </label>
            </fieldset>
            {target === "custom" && (
              <textarea className="textarea" rows={5} spellCheck={false} disabled={running} aria-label="Servers to scan"
                placeholder={"cloudflare.com\nmail.example.com:587\ngit.example.com:22 ssh"} value={hosts} onChange={(e) => setHosts(e.target.value)} />
            )}
            <fieldset className="choice" disabled={running}>
              <legend className="field"><span>What to do</span></legend>
              <label className="choice-item">
                <input type="radio" name="action" checked={action === "scan"} onChange={() => setAction("scan")} />
                <span><b>Scan only</b><small>Handshakes only. Nothing on the servers changes.</small></span>
              </label>
              <label className="choice-item">
                <input type="radio" name="action" checked={action === "fix"} disabled={!canFix} onChange={() => setAction("fix")} />
                <span><b>Scan and fix</b><small>{canFix ? "The agent proposes one line per server; you approve each change." : "Needs the inventory with managed servers"}</small></span>
              </label>
            </fieldset>
            {action === "fix" && canFix && (
              <fieldset className="choice" disabled={running}>
                <legend className="field"><span>Agent</span></legend>
                {[["gemma", "Gemma 4"], ["rules", "Rules, no AI"]].map(([id, label]) => {
                  const p = caps.planners[id];
                  return (
                    <label key={id} className="choice-item">
                      <input type="radio" name="planner" checked={planner === id} disabled={!p?.ok} onChange={() => setPlanner(id)} />
                      <span><b>{label}</b><small>{p?.detail}</small></span>
                    </label>
                  );
                })}
              </fieldset>
            )}
            {error && <p className="error" role="alert">{error}</p>}
            {!caps.jobs && <p className="hint">This dashboard is read-only, so runs are off.</p>}
            {caps.jobs && !perms.has("run") && <p className="hint">Your role ({me.role}) can view results but not start runs.</p>}
            <div className="row">
              <button type="button" className="btn primary" onClick={start} disabled={!canStart || running}>
                {running ? "Running" : action === "fix" && canFix ? "Start scan and fix" : "Start scan"}
              </button>
              {running && <button type="button" className="btn" onClick={cancel}>Cancel</button>}
            </div>
          </div>
        </Panel>

        <section className="panel">
          <div className="panel-head"><div><h2>Progress</h2></div></div>
          {!run ? (
            <Empty title="No run yet">Choose the servers and start a run. Progress and approvals appear here.</Empty>
          ) : (
            <>
              <FleetMap services={run.nodes} caption={<span className="muted">{run.nodes.filter((n) => n.status).length} of {plural(run.nodes.length, "server")} checked</span>} />
              <ol className="steps">
                {STEPS.map((label, i) => (
                  <li key={label} className={`step ${run.state[i]}`}>
                    <span className="step-icon">{run.state[i] === "done" && <Check />}</span>
                    <div><b>{label}</b>{run.notes[i] && <div className="sub">{run.notes[i]}</div>}</div>
                    <span className="sub">{run.state[i] === "skipped" ? "Skipped" : run.state[i] === "failed" ? "Failed" : ""}</span>
                  </li>
                ))}
              </ol>
              {run.pending.map((a) => <ApprovalCard key={a.id} a={a} me={me} perms={perms} onDecide={decide} />)}
              {run.result && <Summary r={run.result} />}
              <details>
                <summary>Log ({run.log.length} lines)</summary>
                <pre className="log">{run.log.join("\n") || "Waiting for output"}</pre>
              </details>
            </>
          )}
        </section>
      </div>
    </>
  );
}

export function ApprovalCard({ a, me, perms, onDecide }) {
  const own = a.require_other && a.initiated_by && a.initiated_by.toLowerCase() === me.identity.toLowerCase();
  const can = perms.has("approve");
  return (
    <div className="approval">
      <div className="approval-head">
        <div>
          <h3>Approve the change to {a.service}?</h3>
          <div className="muted">{a.summary}</div>
        </div>
        <Pill tone="warn">Waiting for approval</Pill>
      </div>
      <Diff text={a.diff} />
      <div className="row mt8">
        <button type="button" className="btn primary" disabled={!can || own} onClick={() => onDecide(a, true)}>Approve and apply</button>
        <button type="button" className="btn danger" disabled={!can} onClick={() => onDecide(a, false)}>Reject</button>
        <span className="hint">
          {!can
            ? `Your role (${me.role}) can see changes but not approve them.`
            : own
              ? "You started this run, so someone else must approve it. You can still reject it."
              : "AegisQ tests the config, reloads the server, checks it from outside, and rolls back if anything fails."}
        </span>
      </div>
    </div>
  );
}

function Summary({ r }) {
  if (r.error) return <div className="approval"><div className="notice risk">{r.error}</div></div>;
  const names = r.fix ? Array.from(new Set([...Object.keys(r.outcomes || {}), ...(r.approvals || []).map((a) => a.service)])) : [];
  return (
    <div className="approval">
      <div className="approval-head">
        <h3>Finished in {((r.finished - r.started) / 1000).toFixed(0)} seconds</h3>
        <a className="btn small" href="#overview">View overview</a>
      </div>
      {r.fix && (names.length ? (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Server</th><th>Before</th><th>After</th><th>Outcome</th><th>Approved by</th></tr></thead>
            <tbody>
              {names.map((n) => {
                const [label, t] = OUTCOME[r.outcomes?.[n]] || ["No change", "idle"];
                const a = (r.approvals || []).filter((x) => x.service === n).pop();
                return (
                  <tr key={n}>
                    <td><b>{n}</b></td>
                    <td><Status status={r.before?.[n]} /></td>
                    <td><Status status={r.after?.[n]} /></td>
                    <td><Pill tone={t}>{label}</Pill></td>
                    <td>{a?.decided_by || <span className="muted">Nobody</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : <p className="muted">The agent found nothing it was allowed to change.</p>)}
      {r.notes && <p className="ink2 mt8">{r.notes}</p>}
    </div>
  );
}
