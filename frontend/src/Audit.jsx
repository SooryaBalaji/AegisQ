export default function Audit({ rows }) {
  return (
    <section className="card" id="audit" aria-labelledby="audit-title">
      <h2 id="audit-title">Audit log</h2>
      <div className="scroll audit-box">
        <table className="data">
          <thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Event</th><th>Detail</th></tr></thead>
          <tbody>{rows.slice().reverse().map((e) => (
            <tr key={e.seq}>
              <td className="num">{e.seq}</td>
              <td className="small mono">{e.ts.slice(0, 19).replace("T", " ")}</td>
              <td>{e.actor}</td><td className="mono">{e.event}</td>
              <td className="small mono">{JSON.stringify(e.data).slice(0, 180)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </section>
  );
}
