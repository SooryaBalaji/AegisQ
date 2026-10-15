import { useState } from "react";
import { startJob } from "./api.js";
import { fmt } from "./util.jsx";

function Results({ bm }) {
  if (!bm) return <p className="muted">Not measured yet. Run a benchmark against a server that supports post-quantum TLS.</p>;
  const sz = bm.sizes;
  return (
    <>
      <div className="scroll">
        <table className="data">
          <thead><tr><th>Setting</th><th className="num">n</th><th className="num">p50 ms</th><th className="num">p99 ms</th><th className="num">Failures</th></tr></thead>
          <tbody>{bm.results.map((r) => (
            <tr key={r.label}>
              <td>{r.label}</td><td className="num">{r.n}</td><td className="num">{fmt(r.p50_ms, 3)}</td>
              <td className="num">{fmt(r.p99_ms, 3)}</td><td className="num">{r.failures}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <p className="small">{`Key shares — client: ${sz.client_key_share.pq} vs ${sz.client_key_share.classical} bytes; server: ${sz.server_key_share.pq} vs ${sz.server_key_share.classical} bytes; +${sz.extra_bytes_per_handshake} bytes per handshake.`}</p>
      <p className="small">{sz.packet_split}</p>
      <p className="muted small">{bm.caveat}</p>
    </>
  );
}

function Form({ client, jobs, loadJobs, signOut, canRun }) {
  const [url, setUrl] = useState("");
  const [n, setN] = useState(200);
  const [method, setMethod] = useState("auto");
  const [busy, setBusy] = useState(false);
  const running = jobs.some((j) => j.kind === "benchmark" && j.status === "running");
  const submit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setBusy(true);
    await startJob(client, { kind: "benchmark", url: url.trim(), n: Number(n) || 200, method }, loadJobs, signOut);
    setBusy(false);
  };
  return (
    <form className="run-card" onSubmit={submit}>
      <h3>Measure a server</h3>
      <label htmlFor="bench-url">HTTPS server that supports post-quantum TLS</label>
      <input id="bench-url" type="url" required placeholder="https://cloudflare.com/" spellCheck={false} value={url} onChange={(e) => setUrl(e.target.value)} />
      <div className="inline">
        <label htmlFor="bench-n">Handshakes</label>
        <input id="bench-n" type="number" min={10} max={5000} value={n} onChange={(e) => setN(e.target.value)} />
        <label htmlFor="bench-method">Method</label>
        <select id="bench-method" value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="auto">auto</option><option value="native">native</option><option value="curl">curl</option>
        </select>
      </div>
      <div className="btns"><button type="submit" disabled={busy || running || !canRun} title={canRun ? "" : "Your role cannot start jobs"}>{running ? "Running…" : "Run benchmark"}</button></div>
      <p className="muted small">Compares hybrid X25519MLKEM768 with classical X25519 handshakes against the same server.</p>
    </form>
  );
}

export default function Measure({ benchmark, client, jobs, loadJobs, signOut, canRun }) {
  return (
    <section className="card" id="measure" aria-labelledby="bm-title">
      <h2 id="bm-title">Handshake cost <span className="muted">post-quantum vs classical, measured</span></h2>
      <div className="grid2">
        <Form client={client} jobs={jobs} loadJobs={loadJobs} signOut={signOut} canRun={canRun} />
        <div><Results bm={benchmark} /></div>
      </div>
    </section>
  );
}
