import { fmt } from "./util.jsx";

function RealWorld({ rw }) {
  if (!rw) return <p className="muted">Not measured yet: use <a href="#run">Run → Measure</a>.</p>;
  return (
    <>
      <div className="scroll">
        <table className="data">
          <thead><tr><th>Group</th><th className="num">Reachable</th><th className="num">PQ ready</th><th className="num">Share</th><th className="num">Failed</th></tr></thead>
          <tbody>{rw.groups.map((g) => (
            <tr key={g.label}>
              <td>{g.label}</td><td className="num">{g.reachable}</td><td className="num">{g.pq_ready}</td>
              <td className="num">{g.pq_pct}%</td><td className="num">{g.failed_to_connect}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <p className="muted small">{`${rw.method}. Tranco list ${rw.list_id}, seed ${rw.seed}, ${rw.duration_s} s.`}</p>
    </>
  );
}

function Benchmark({ bm }) {
  if (!bm) return <p className="muted">Not measured yet: use <a href="#run">Run → Measure</a>.</p>;
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

export default function Measure({ realworld, benchmark }) {
  return (
    <section className="grid2" id="measure">
      <div className="card" aria-labelledby="rw-title"><h2 id="rw-title">Real-world adoption gap</h2><RealWorld rw={realworld} /></div>
      <div className="card" aria-labelledby="bm-title"><h2 id="bm-title">Handshake cost</h2><Benchmark bm={benchmark} /></div>
    </section>
  );
}
