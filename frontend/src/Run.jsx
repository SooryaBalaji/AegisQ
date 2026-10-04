import { useEffect, useRef, useState } from "react";
import { startJob } from "./api.js";
import { Badge, JOB_STATUS, duration } from "./util.jsx";

const optionLabel = (label, item) => (item && !item.ok ? `${label} — ${item.detail}` : label);

function ScanCard({ caps, run }) {
  const [targets, setTargets] = useState("");
  const disabled = !caps || !caps.jobs;
  return (
    <form className="run-card" onSubmit={(e) => {
      e.preventDefault();
      if (!targets.trim()) { alert("Enter at least one server, one per line."); return; }
      run({ kind: "scan", targets: targets.trim() });
    }}>
      <h3>1 · Scan servers</h3>
      <label htmlFor="targets">One per line: <code>host[:port] [tls|ssh] [data category]</code></label>
      <textarea id="targets" rows={6} spellCheck={false} disabled={disabled} value={targets} onChange={(e) => setTargets(e.target.value)}
        placeholder={"cloudflare.com\nwww.google.com\ngithub.com:22 ssh\nmail.example.com:993 tls payments"} />
      <div className="btns">
        <button type="submit" disabled={disabled}>Scan these servers</button>
        <button type="button" className="ghost" disabled={disabled || !caps.inventory}
          title={caps && caps.inventory ? "" : "Start the dashboard with --inventory FILE"}
          onClick={() => run({ kind: "scan" })}>Scan the inventory</button>
      </div>
      <p className="muted small">Each server gets real post-quantum TLS/SSH handshakes. Nothing is changed.</p>
    </form>
  );
}

function MigrateCard({ caps, run }) {
  const p = caps && caps.planners;
  const managed = caps ? caps.services.filter((s) => s.managed) : [];
  const [planner, setPlanner] = useState("rules");
  const [unchecked, setUnchecked] = useState(() => new Set());
  useEffect(() => { if (p && p.local.ok) setPlanner("local"); }, [p]);
  const disabled = !caps || !caps.jobs;
  const toggle = (name) => setUnchecked((s) => {
    const n = new Set(s);
    if (n.has(name)) n.delete(name); else n.add(name);
    return n;
  });
  return (
    <form className="run-card" onSubmit={(e) => {
      e.preventDefault();
      const chosen = managed.map((s) => s.name).filter((n) => !unchecked.has(n));
      if (!chosen.length) { alert("Pick at least one service."); return; }
      run({ kind: "migrate", planner, services: chosen.length === managed.length ? [] : chosen });
    }}>
      <h3>2 · Fix with the agent</h3>
      <label htmlFor="planner">Planner</label>
      <select id="planner" value={planner} disabled={disabled} onChange={(e) => setPlanner(e.target.value)}>
        <option value="local" disabled={!p || !p.local.ok}>{optionLabel("Gemma 4 / local model", p && p.local)}</option>
        <option value="rules">Rules (deterministic, no AI)</option>
        <option value="claude" disabled={!p || !p.claude.ok}>{optionLabel("Claude", p && p.claude)}</option>
      </select>
      <fieldset>
        <legend>Managed services</legend>
        <div className="checks">
          {managed.length > 0 ? managed.map((s) => (
            <label className="check" key={s.name}>
              <input type="checkbox" checked={!unchecked.has(s.name)} disabled={disabled} onChange={() => toggle(s.name)} />
              {` ${s.name} `}<span className="muted small mono">{s.endpoint}</span>
            </label>
          )) : (
            <p className="muted small">{caps && caps.inventory ? "The inventory has no managed services." : "Start the dashboard with --inventory FILE to migrate servers you manage."}</p>
          )}
        </div>
      </fieldset>
      <div className="btns"><button type="submit" disabled={disabled || !managed.length}>Start migration</button></div>
      <p className="muted small">The agent proposes each change and waits: approve it in <a href="#approvals">Approvals</a>. Failures roll back automatically.</p>
    </form>
  );
}

function QuantumCard({ caps, run }) {
  const [source, setSource] = useState("simulated");
  const [backend, setBackend] = useState("aer");
  const disabled = !caps || !caps.jobs;
  const ibmOk = caps && caps.ibm && caps.ibm.ok;
  const qOk = caps && caps.quantum && caps.quantum.ok;
  const ibmLabel = ibmOk || !caps || !caps.ibm ? "IBM quantum hardware" : `IBM quantum hardware — ${caps.ibm.detail}`;
  return (
    <form className="run-card" onSubmit={(e) => { e.preventDefault(); run({ kind: "entropy", source }); }}>
      <h3>3 · Quantum</h3>
      <label htmlFor="ent-source">Entropy source</label>
      <select id="ent-source" value={source} disabled={disabled} onChange={(e) => setSource(e.target.value)}>
        <option value="simulated">Simulator (~5 s, not quantum)</option>
        <option value="ibm" disabled={!ibmOk}>{ibmOk ? "IBM quantum hardware (may queue)" : ibmLabel}</option>
      </select>
      <div className="btns">
        <button type="submit" disabled={disabled || !qOk} title={qOk || !caps || !caps.quantum ? "" : caps.quantum.detail}>Run entropy job</button>
      </div>
      <label htmlFor="shor-backend">Shor's algorithm (N = 15)</label>
      <select id="shor-backend" value={backend} disabled={disabled} onChange={(e) => setBackend(e.target.value)}>
        <option value="aer">Simulator</option>
        <option value="ibm" disabled={!ibmOk}>{ibmLabel}</option>
      </select>
      <div className="btns">
        <button type="button" className="ghost" disabled={disabled || !qOk} onClick={() => run({ kind: "shor", backend })}>Run Shor</button>
      </div>
    </form>
  );
}

function MeasureCard({ caps, run }) {
  const [url, setUrl] = useState("");
  const [n, setN] = useState(200);
  const [method, setMethod] = useState("auto");
  const disabled = !caps || !caps.jobs;
  return (
    <form className="run-card" onSubmit={(e) => {
      e.preventDefault();
      if (!url.trim()) { alert("Enter an https:// URL of a server to benchmark."); return; }
      run({ kind: "benchmark", url: url.trim(), n: Number(n) || 200, method });
    }}>
      <h3>4 · Measure</h3>
      <label htmlFor="bench-url">Handshake benchmark: a PQ-ready HTTPS server</label>
      <input id="bench-url" type="url" placeholder="https://cloudflare.com/" spellCheck={false} disabled={disabled}
        value={url} onChange={(e) => setUrl(e.target.value)} />
      <div className="inline">
        <label htmlFor="bench-n">Handshakes</label>
        <input id="bench-n" type="number" min={10} max={5000} disabled={disabled} value={n} onChange={(e) => setN(e.target.value)} />
        <label htmlFor="bench-method">Method</label>
        <select id="bench-method" value={method} disabled={disabled} onChange={(e) => setMethod(e.target.value)}>
          <option value="auto">auto</option><option value="native">native</option><option value="curl">curl</option>
        </select>
      </div>
      <div className="btns"><button type="submit" disabled={disabled}>Run benchmark</button></div>
      <label>Real-world adoption gap</label>
      <div className="btns">
        <button type="button" className="ghost" disabled={disabled} onClick={() => run({ kind: "realworld" })}>Scan top vs long-tail sites</button>
      </div>
      <p className="muted small">Downloads the Tranco list and probes 1,000 sites (a few minutes).</p>
    </form>
  );
}

function JobView({ client, id, onClose, loadJobs }) {
  const [lines, setLines] = useState([]);
  const [info, setInfo] = useState(null);
  const logRef = useRef(null);
  const since = useRef(0);

  useEffect(() => {
    since.current = 0;
    setLines([]); setInfo(null);
    let live = true;
    let timer = null;
    const poll = async () => {
      let d;
      try { d = await client.api(`/api/jobs/${encodeURIComponent(id)}?since=${since.current}`); } catch { return; }
      if (!live || !d) return;
      const el = logRef.current;
      const atBottom = !el || el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      if (d.log.length) setLines((l) => l.concat(d.log));
      since.current = d.since + d.log.length;
      setInfo(d);
      if (atBottom) requestAnimationFrame(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; });
      if (d.status !== "running") { clearInterval(timer); loadJobs(); }
    };
    poll();
    timer = setInterval(poll, 1000);
    logRef.current?.scrollIntoView({ block: "nearest" });
    return () => { live = false; clearInterval(timer); };
  }, [client, id, loadJobs]);

  const cancel = async () => {
    if (!confirm("Cancel this job? A migration rolls back anything not yet verified.")) return;
    try { await client.api(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: "POST" }); } catch (e) { alert(e.message); }
  };

  const label = info ? (JOB_STATUS[info.status] || ["", info.status])[1] : "";
  const exit = info && info.exit_code !== null && info.status !== "running" ? ` (exit ${info.exit_code})` : "";
  return (
    <div className="job-view">
      <div className="row-between">
        <strong>{info ? `${info.label} — ${label}${exit}` : "Loading…"}</strong>
        <span>
          <button type="button" className="ghost" disabled={!info || info.status !== "running"} onClick={cancel}>Cancel</button>{" "}
          <button type="button" className="ghost" onClick={onClose}>Close</button>
        </span>
      </div>
      <pre ref={logRef} className="log" tabIndex={0} aria-label="Job output" aria-live="polite">{lines.join("\n")}{lines.length ? "\n" : ""}</pre>
    </div>
  );
}

export default function Run({ client, caps, jobs, pending, loadJobs, signOut }) {
  const [openId, setOpenId] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async (payload) => {
    if (busy) return;
    setBusy(true);
    const job = await startJob(client, payload, loadJobs, signOut);
    setBusy(false);
    if (job) setOpenId(job.id);
  };

  return (
    <section className="card" id="run" aria-labelledby="run-title">
      <h2 id="run-title">Run <span className="muted small">every button runs the real aegisq command; output streams below</span></h2>
      {pending.length > 0 && (
        <a className="pending-banner" href="#approvals">
          {`${pending.length} change${pending.length > 1 ? "s" : ""} waiting for your approval (${pending.map((a) => a.service).join(", ")}) → review`}
        </a>
      )}
      {caps && !caps.jobs && <p className="warn-banner">This dashboard was started with <code>--read-only</code>: results only.</p>}
      <div className="run-grid">
        <ScanCard caps={caps} run={run} />
        <MigrateCard caps={caps} run={run} />
        <QuantumCard caps={caps} run={run} />
        <MeasureCard caps={caps} run={run} />
      </div>

      <h3 className="jobs-title">Jobs</h3>
      {jobs.length > 0 ? (
        <div className="scroll">
          <table className="data">
            <thead><tr><th>Job</th><th>Started by</th><th>Status</th><th>Time</th><th>Latest output</th><th></th></tr></thead>
            <tbody>{jobs.map((j) => {
              const [k, l] = JOB_STATUS[j.status] || ["muted", j.status];
              return (
                <tr key={j.id}>
                  <td>{j.label}</td><td>{j.started_by}</td><td><Badge kind={k}>{l}</Badge></td>
                  <td className="small">{duration(j)}</td><td className="small mono clip">{j.last_line}</td>
                  <td><button type="button" className="ghost small-btn" onClick={() => setOpenId(j.id)}>Output</button></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      ) : <p className="muted">Nothing has run from the dashboard yet.</p>}
      {openId && <JobView key={openId} client={client} id={openId} loadJobs={loadJobs} onClose={() => setOpenId(null)} />}
    </section>
  );
}
