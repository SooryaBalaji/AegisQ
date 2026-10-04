import { Fragment, useState } from "react";
import { Badge, SEV, STATUS, fmt, marginOf, severity, why, years } from "./util.jsx";

function Tile({ k, v, l }) {
  return <div className="tile"><div className="k">{k}</div><div className="v">{v}</div><div className="l">{l}</div></div>;
}

function Hero({ overview, z }) {
  const scan = overview && overview.scan;
  let title = "Find it. Rank it. Fix it safely.";
  let sub = "Every TLS and SSH service probed with a real post-quantum handshake, ranked by Mosca risk, and migrated by an agent that waits for a named human at every step.";
  let tiles = null;
  if (scan) {
    const sm = scan.summary;
    const reachable = sm.total - sm.unreachable - sm.error;
    const pct = reachable ? Math.round((100 * sm.pq_ready) / reachable) : 0;
    const atRisk = overview.services.filter((r) => ["critical", "high"].includes(severity(marginOf(r, z), r.status))).length;
    title = reachable ? `${pct}% of your fleet is quantum-safe.` : "No reachable services yet.";
    sub = `${atRisk} of ${sm.total} services hold data that is already exposed to harvest-now, decrypt-later at Z = ${z} years. ` +
      "Every fix is proposed by the agent, approved by a named person, tested, verified, and rolled back if it fails.";
    tiles = (
      <>
        <Tile k="Post-quantum ready" v={`${pct}%`} l={`${sm.pq_ready} of ${reachable} reachable services complete a hybrid ML-KEM handshake`} />
        <Tile k="At risk now" v={atRisk} l={`X + Y > Z at Z = ${z}`} />
        <Tile k="Scanned" v={sm.total} l="TLS and SSH services" />
        <Tile k="Classical or old TLS" v={sm.classical + sm.tls12_only + sm.legacy_tls} l="need a key-exchange upgrade" />
        <Tile k="Plaintext HTTP" v={sm.plaintext} l="readable today" />
      </>
    );
  }
  return (
    <section className="hero" id="top" aria-labelledby="hero-title">
      <div className="hero-copy">
        <span className="eyebrow">Upgrade your key exchange</span>
        <h1 id="hero-title" className="display">{title}</h1>
        <p className="lede">{sub}</p>
        <div className="hero-cta">
          <a className="button pill" href="#run">Scan your servers</a>
          <a className="button pill-ghost" href="#approvals">Review approvals</a>
        </div>
      </div>
      <div className="tiles" aria-label="Summary">{tiles}</div>
    </section>
  );
}

function Fact({ k, v }) {
  return <div className="fact"><span className="fact-k">{k}</span><span>{v}</span></div>;
}

function ServerRow({ r, i }) {
  const [open, setOpen] = useState(false);
  const [sk, sl] = STATUS[r.status] || ["muted", r.status];
  const toggle = () => setOpen((o) => !o);
  const noMargin = ["pq_ready", "unreachable", "error"].includes(r.status);
  return (
    <Fragment>
      <tr className="expandable" tabIndex={0} aria-expanded={open} onClick={toggle}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } }}>
        <td className="num muted">{i + 1}</td>
        <td>
          <div className="svc">{r.name}</div>
          <div className="muted small mono">{r.endpoint}</div>
          <div className="phone-only"><Badge kind={sk}>{sl}</Badge></div>
        </td>
        <td><Badge kind={sk}>{sl}</Badge></td>
        <td>{r.data_category}</td>
        <td><Badge kind={SEV[r.sev]}>{r.sev === "none" ? "safe" : r.sev}</Badge><div className="why">{why(r)}</div></td>
        <td className="chev" aria-hidden="true"><span>›</span></td>
      </tr>
      {open && (
        <tr className="detail">
          <td colSpan={6}>
            <div className="facts">
              <Fact k="Key exchange" v={r.group || "–"} />
              <Fact k="Data must stay secret for" v={`${years(r.x)} (${r.data_category} data, X)`} />
              <Fact k="Time to fix" v={`${years(r.y)}: ${r.y_reason} (Y)`} />
              {!noMargin && (
                <Fact k="Margin" v={`X + Y − Z = ${r.margin > 0 ? "+" : ""}${fmt(r.margin)} years${r.status === "plaintext" ? " (Z ignored: readable today)" : ""}`} />
              )}
              <Fact k="Managed" v={r.managed ? "Yes: the agent can propose a fix." : "No: scan only. Hand this to the server's owner."} />
            </div>
            {r.findings.length > 0 && <ul className="findings">{r.findings.map((f, k) => <li key={k}>{f}</li>)}</ul>}
            {r.errors.length > 0 && <div className="bad">{r.errors.join("; ")}</div>}
          </td>
        </tr>
      )}
    </Fragment>
  );
}

function Risk({ overview, z, setZ, client, onRescan }) {
  const scan = overview && overview.scan;
  const rows = (overview ? overview.services : []).map((r) => {
    const margin = marginOf(r, z);
    return { ...r, margin, sev: severity(margin, r.status) };
  });
  const group = (r) => (r.sev === "none" ? 2 : r.sev === "unknown" ? 1 : 0);
  rows.sort((a, b) => group(a) - group(b) || b.margin - a.margin || b.x - a.x || a.name.localeCompare(b.name));
  const exposed = rows.filter((r) => r.sev === "critical" || r.sev === "high").map((r) => r.name);
  const canRescan = overview && overview.can_rescan;

  return (
    <section className="card" id="risk" aria-labelledby="mosca-title">
      <div className="row-between">
        <h2 id="mosca-title">Which servers are at risk?</h2>
        <div className="actions">
          <button className="ghost" type="button" disabled={!canRescan} onClick={onRescan}
            title={canRescan ? "" : "Start `aegisq serve --inventory FILE` to enable"}>Rescan fleet</button>
          <a className="button ghost" href="#" onClick={(e) => { e.preventDefault(); client.download("/api/cbom", "cbom.json"); }}>Download CBOM</a>
        </div>
      </div>
      <p className="intro">A server is at risk when its data must stay secret for longer than it will take to build a quantum computer that can break it, minus the time needed to fix the server. Nobody knows that date, so try different guesses with the slider.</p>
      <div className="z-box">
        <label htmlFor="z">A quantum computer could break today's encryption in</label>
        <div className="slider-row">
          <input id="z" type="range" min="0" max="30" step="0.5" value={z} onChange={(e) => setZ(Number(e.target.value))} />
          <output htmlFor="z">{z}</output><span className="unit">years</span>
        </div>
        <div className="z-summary" aria-live="polite">
          {scan && (exposed.length === 0
            ? <span className="z-ok">In {years(z)}: no server has data already at risk.</span>
            : <><span>In {years(z)}: <strong>{exposed.length} at risk now</strong></span>{exposed.map((n) => <span key={n} className="chip">{n}</span>)}</>)}
        </div>
        {overview && (
          <details className="sources">
            <summary>Where does this guess come from?</summary>
            <div className="scroll">
              <table>
                <thead><tr><th>Estimate</th><th>Target</th><th>Logical qubits</th><th>Physical qubits</th><th>Runtime</th></tr></thead>
                <tbody>{overview.estimates.map((e, k) => (
                  <tr key={k}><td>{e.estimate}</td><td>{e.target}</td><td>{e.logical_qubits}</td><td>{e.physical_qubits}</td><td>{e.runtime}</td></tr>
                ))}</tbody>
              </table>
            </div>
            <p className="muted small">{overview.estimate_note}</p>
          </details>
        )}
      </div>
      <div className="scroll">
        <table className="data ranking">
          <thead><tr><th className="num">#</th><th>Server</th><th>Status</th><th>Data</th><th>Risk</th><th aria-label="Details"></th></tr></thead>
          <tbody>{rows.map((r, i) => <ServerRow key={r.name} r={r} i={i} />)}</tbody>
        </table>
      </div>
      {scan
        ? <p className="muted small">Click a server to see why it got its risk.</p>
        : <p className="muted">No scan yet: go to <a href="#run">Run</a>, enter some servers and click <em>Scan these servers</em>.</p>}
    </section>
  );
}

export default function Overview(props) {
  return (
    <>
      <Hero overview={props.overview} z={props.z} />
      <Risk {...props} />
    </>
  );
}
