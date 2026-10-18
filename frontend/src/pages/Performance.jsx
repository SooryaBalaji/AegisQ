import { useEffect, useState } from "react";
import { api, followJob } from "../api.js";
import { Empty, PageHead, Panel, when } from "../ui.jsx";

const ms = (v) => (v == null ? "" : v.toFixed(2));

export default function Performance({ perms, guard, toast }) {
  const [bm, setBm] = useState(null);
  const [url, setUrl] = useState("https://cloudflare.com/");
  const [n, setN] = useState(200);
  const [busy, setBusy] = useState(false);
  const load = () => guard(async () => setBm(await api("/api/benchmark")));
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const run = (e) => {
    e.preventDefault();
    guard(async () => {
      setBusy(true);
      try {
        const job = await api("/api/jobs", { method: "POST", body: { kind: "benchmark", url: url.trim(), n: Number(n) || 200, method: "auto" } });
        const done = await followJob(job.id, () => {}, () => true);
        if (done.status !== "succeeded") toast(done.lines.slice(-1)[0] || "The measurement failed.");
        await load();
      } finally {
        setBusy(false);
      }
    });
  };

  const pq = bm?.results?.find((r) => /mlkem/i.test(r.label));
  const cl = bm?.results?.find((r) => !/mlkem/i.test(r.label));
  const sz = bm?.sizes;

  return (
    <>
      <PageHead title="Performance">
        What switching costs: the same server, measured with a post-quantum hybrid handshake and a classical one.
      </PageHead>
      <div className="grid-run">
        <Panel title="Measure a server">
          <form className="form" onSubmit={run}>
            <label className="field">
              <span>HTTPS address</span>
              <input className="input" type="url" required spellCheck={false} value={url} onChange={(e) => setUrl(e.target.value)} />
              <small>It must support post-quantum TLS, or every hybrid handshake fails.</small>
            </label>
            <label className="field">
              <span>Handshakes per setting</span>
              <input className="input" type="number" min={10} max={5000} value={n} onChange={(e) => setN(e.target.value)} />
            </label>
            <div className="row">
              <button className="btn primary" type="submit" disabled={busy || !perms.has("run")}>{busy ? "Measuring" : "Measure"}</button>
            </div>
          </form>
        </Panel>
        <Panel title="Latest measurement" sub={bm ? `${bm.url}, ${when(bm.measured_at || bm.finished_at)}` : null} flush>
          {!bm ? (
            <Empty title="Not measured yet">Measure a server that supports post-quantum TLS, such as cloudflare.com.</Empty>
          ) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>Handshake</th><th className="num">Runs</th><th className="num">Median ms</th><th className="num">99th pct ms</th><th className="num">Failed</th></tr></thead>
                  <tbody>
                    {bm.results.map((r) => (
                      <tr key={r.label}>
                        <td>{r.label}{r.note && <div className="sub">{r.note}</div>}</td>
                        <td className="num">{r.n}</td>
                        <td className="num">{ms(r.p50_ms)}</td>
                        <td className="num">{ms(r.p99_ms)}</td>
                        <td className="num">{r.failures}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="panel-body">
                {pq && cl && pq.p50_ms != null && cl.p50_ms != null && (
                  <p>The hybrid handshake took {(pq.p50_ms - cl.p50_ms).toFixed(2)} ms {pq.p50_ms >= cl.p50_ms ? "longer" : "less"} at the median.</p>
                )}
                {sz && (
                  <p className="ink2 mt8">
                    The client sends {sz.client_key_share.pq} bytes of key share instead of {sz.client_key_share.classical}, and the server
                    answers with {sz.server_key_share.pq} instead of {sz.server_key_share.classical}: {sz.extra_bytes_per_handshake} extra
                    bytes per handshake. {sz.packet_split}
                  </p>
                )}
                <p className="hint mt8">{bm.caveat}</p>
              </div>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}
