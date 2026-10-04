import { useEffect, useRef, useState } from "react";

function Tooltip({ tip }) {
  const ref = useRef(null);
  const [pos, setPos] = useState({ left: 0, top: 0 });
  useEffect(() => {
    if (!tip || !ref.current) return;
    const pad = 12;
    const r = ref.current.getBoundingClientRect();
    let x = tip.x + pad;
    let y = tip.y + pad;
    if (x + r.width > window.innerWidth) x = tip.x - r.width - pad;
    if (y + r.height > window.innerHeight) y = tip.y - r.height - pad;
    setPos({ left: Math.max(4, x), top: Math.max(4, y) });
  }, [tip]);
  if (!tip) return null;
  return (
    <div ref={ref} className="tooltip" role="status" style={pos}>
      {tip.lines.map((l, i) => (i === 0 ? <strong key={i}>{l}</strong> : <div key={i}>{l}</div>))}
    </div>
  );
}

function BarChart({ labels, series, refs = [], yMin, yMax, valueFmt = (v) => v.toFixed(4), title, setTip }) {
  const W = 640, H = 200, L = 46, R = 8, T = 8, B = 22;
  const n = labels.length, k = series.length;
  const y = (v) => T + (H - T - B) * (1 - (v - yMin) / (yMax - yMin));
  const gw = (W - L - R) / n;
  const bw = Math.max(1, (gw - (gw > 4 ? 1 : 0)) / k);
  const zero = y(Math.max(yMin, Math.min(0, yMax)));
  const ticks = [0, 1, 2, 3, 4].map((i) => yMin + ((yMax - yMin) * i) / 4);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={title}>
      {ticks.map((v, i) => (
        <g key={i}>
          <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className="gridline" />
          <text x={L - 4} y={y(v) + 3} textAnchor="end" className="axis-text">{valueFmt(v)}</text>
        </g>
      ))}
      {labels.map((lab, i) => (
        <g key={lab}>
          {series.map((ser, j) => {
            const yy = y(Math.max(yMin, Math.min(yMax, ser.values[i])));
            return (
              <rect key={j} x={L + i * gw + j * bw} y={Math.min(yy, zero)} width={Math.max(0.6, bw - (k > 1 ? 0.3 : 0))}
                height={Math.max(0.5, Math.abs(zero - yy))} className={ser.cls} rx={bw > 6 ? 2 : 0} />
            );
          })}
          <rect x={L + i * gw} y={T} width={gw} height={H - T - B} className="hit"
            onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, lines: [lab, ...series.map((ser) => `${ser.name}: ${valueFmt(ser.values[i])}`)] })}
            onMouseLeave={() => setTip(null)} />
        </g>
      ))}
      {refs.map((r, i) => (
        <g key={`r${i}`}>
          <line x1={L} x2={W - R} y1={y(r.v)} y2={y(r.v)} className="ref" />
          <text x={W - R - 2} y={y(r.v) - 3} textAnchor="end" className="axis-text">{r.label}</text>
        </g>
      ))}
      <text x={L} y={H - 6} className="axis-text">{`${n} qubits, ordered by readout quality`}</text>
    </svg>
  );
}

function Heatmap({ matrix, qubits, band, setTip }) {
  const ref = useRef(null);
  const n = matrix.length;
  const px = Math.max(3, Math.floor(400 / n));
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const parse = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
    const neg = parse(css("--div-neg")), mid = parse(css("--div-mid")), pos = parse(css("--div-pos"));
    const m = Math.max(band * 3, 0.05);
    const mix = (a, b, t) => a.map((x, i) => Math.round(x + (b[i] - x) * t));
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
      const v = i === j ? 0 : matrix[i][j];
      const t = Math.min(1, Math.abs(v) / m);
      const [r, g, b] = v < 0 ? mix(mid, neg, t) : mix(mid, pos, t);
      ctx.fillStyle = `rgb(${r},${g},${b})`;
      ctx.fillRect(j * px, i * px, px, px);
    }
  }, [matrix, band, n, px]);
  const move = (e) => {
    const rect = ref.current.getBoundingClientRect();
    const j = Math.floor(((e.clientX - rect.left) / rect.width) * n);
    const i = Math.floor(((e.clientY - rect.top) / rect.height) * n);
    if (i < 0 || j < 0 || i >= n || j >= n) { setTip(null); return; }
    setTip({ x: e.clientX, y: e.clientY, lines: [`qubits ${qubits[i]} × ${qubits[j]}`, i === j ? "diagonal" : `r = ${matrix[i][j].toFixed(4)}`, `chance band ±${band.toFixed(3)}`] });
  };
  return <canvas ref={ref} width={n * px} height={n * px} role="img" aria-label="Qubit-to-qubit correlation heatmap"
    onMouseMove={move} onMouseLeave={() => setTip(null)} />;
}

function ChartBox({ title, sub, legend, children }) {
  return (
    <div className="chart">
      <h3>{title}</h3>
      {sub && <p className="muted small">{sub}</p>}
      {legend}
      {children}
    </div>
  );
}

function KV({ pairs }) {
  return <dl className="kv">{pairs.map(([k, v]) => [<dt key={`${k}-t`}>{k}</dt>, <dd key={`${k}-d`}>{v}</dd>])}</dl>;
}

function Entropy({ d, setTip }) {
  if (!d) return <p className="muted">No entropy run yet: use <a href="#run">Run → Quantum</a>.</p>;
  const q = d.qubits.map((x) => `qubit ${x}`);
  const band = d.noise_band;
  const absMax = (arr, floor) => Math.max(floor, ...arr.map(Math.abs)) * 1.15;
  const errMax = Math.max(0.01, ...d.readout_error_p01, ...d.readout_error_p10) * 1.15;
  const tests = (side) => d.tests[side].map((t) => `${t.test}: p = ${t.p_value.toFixed(3)} ${t.pass ? "✓ pass" : "✗ FAIL"}`).join(" · ");
  return (
    <>
      {d.warning && <div className="warn-banner"><strong>Simulated run. </strong>{d.warning}</div>}
      <div className="grid2">
        <KV pairs={[
          ["Backend", d.backend], ["IBM job ID", d.job_id || "– (not a hardware job)"], ["Created", d.created],
          ["Raw bits", `${d.raw_bits.toLocaleString()} (${d.qubits.length} qubits × ${d.shots.toLocaleString()} shots)`],
          ["Min-entropy h", `${d.h_min.toFixed(4)} bits/bit (worst qubit ${d.worst_qubit}, SP 800-90B MCV, 99%)`],
          ["Extractor", `${d.extractor.type}: ${d.extractor.blocks} × ${d.extractor.block_in.toLocaleString()} → ${d.extractor.block_out.toLocaleString()} bits`],
          ["Output", `${d.extracted_bits.toLocaleString()} bits at ε = 2^-${d.eps_bits}`],
          ["Key fingerprint", d.key_fingerprint_sha256],
        ]} />
        <KV pairs={[
          ["Extracted bits", tests("extracted")], ["os.urandom", tests("os_urandom")],
          ["Correlations", `max |r| ${d.correlation_max_abs_offdiag.toFixed(4)}; ${d.correlation_outside_band} pairs outside ±${band.toFixed(3)}`],
          ["Autocorrelation", `${d.autocorr_outside_band} qubits outside ±${band.toFixed(3)} (expect ~5% by chance)`],
          ["Note", d.tests.note],
        ]} />
      </div>
      <div className="charts">
        <ChartBox title="Readout error per qubit" sub="Measured in the same job from the |0⟩ and |1⟩ calibration circuits"
          legend={<div className="legend"><span><i className="sw1" />P(1 | prepared 0)</span><span><i className="sw2" />P(0 | prepared 1)</span></div>}>
          <BarChart labels={q} setTip={setTip} title="Readout error per qubit" yMin={0} yMax={errMax}
            series={[{ name: "P(1|0)", cls: "bar1", values: d.readout_error_p01 }, { name: "P(0|1)", cls: "bar2", values: d.readout_error_p10 }]} />
        </ChartBox>
        <ChartBox title="Raw bias per qubit" sub="Mean of raw bits − 0.5 (negative = leans to 0, from |1⟩ relaxing during readout)">
          <BarChart labels={q} setTip={setTip} title="Bias per qubit" yMin={-absMax(d.bias, 0.02)} yMax={absMax(d.bias, 0.02)}
            series={[{ name: "bias", cls: "bar1", values: d.bias }]} refs={[{ v: band / 2, label: "" }]} />
        </ChartBox>
        <ChartBox title="Min-entropy per qubit" sub="The smallest value becomes h for extraction (conservative)">
          <BarChart labels={q} setTip={setTip} title="Min-entropy per qubit"
            yMin={Math.max(0, Math.min(...d.min_entropy_per_qubit) - 0.05)} yMax={1}
            series={[{ name: "h", cls: "bar1", values: d.min_entropy_per_qubit }]} refs={[{ v: d.h_min, label: `h = ${d.h_min.toFixed(3)}` }]} />
        </ChartBox>
        <ChartBox title="Lag-1 autocorrelation (shot to shot)" sub={`Dashed lines: ±${band.toFixed(3)}, what chance alone gives`}>
          <BarChart labels={q} setTip={setTip} title="Autocorrelation"
            yMin={-absMax(d.autocorr_lag1, band * 1.5)} yMax={absMax(d.autocorr_lag1, band * 1.5)}
            series={[{ name: "r", cls: "bar1", values: d.autocorr_lag1 }]}
            refs={[{ v: band, label: `+${band.toFixed(3)}` }, { v: -band, label: `−${band.toFixed(3)}` }]} />
        </ChartBox>
        <ChartBox title="Qubit-to-qubit correlation" sub={`Diverging scale saturates at ±${Math.max(band * 3, 0.05).toFixed(3)}; gray = no correlation`}
          legend={<div className="legend"><span><i className="swneg" />negative</span><span><i className="swmid" />≈ 0</span><span><i className="swpos" />positive</span></div>}>
          <Heatmap matrix={d.correlation_matrix} qubits={d.qubits} band={band} setTip={setTip} />
        </ChartBox>
      </div>
      <h3>What is and isn't guaranteed</h3>
      <div className="scroll">
        <table className="data">
          <thead><tr><th>Claim</th><th>Status</th><th>Why</th></tr></thead>
          <tbody>{d.guarantees.map((g) => <tr key={g.claim}><td>{g.claim}</td><td>{g.status}</td><td>{g.why}</td></tr>)}</tbody>
        </table>
      </div>
    </>
  );
}

function Shor({ sh }) {
  if (!sh) return <p className="muted">Not run yet: use <a href="#run">Run → Quantum</a>.</p>;
  return (
    <>
      <p>{`Order finding for N = ${sh.N}, a = ${sh.a} on ${sh.backend}${sh.job_id ? ` (job ${sh.job_id})` : ""}: period r = ${sh.period ?? "not found"}, factors ${sh.factors.length ? sh.factors.join(" × ") : "–"}.`}</p>
      <div className="scroll">
        <table className="data">
          <thead><tr><th>Measured</th><th className="num">Share</th><th>Phase</th><th className="num">r guess</th></tr></thead>
          <tbody>{sh.outcomes.slice(0, 8).map((o) => (
            <tr key={o.bits}><td className="mono">{o.bits}</td><td className="num">{`${(o.share * 100).toFixed(1)}%`}</td><td>{o.fraction}</td><td className="num">{o.r}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <p className="muted small">{sh.disclaimer}</p>
    </>
  );
}

export default function Quantum({ entropy, shor }) {
  const [tip, setTip] = useState(null);
  return (
    <>
      <section className="card" id="entropy-section" aria-labelledby="ent-title">
        <h2 id="ent-title">Quantum entropy</h2>
        <Entropy d={entropy} setTip={setTip} />
      </section>
      <section className="card" id="shor-section" aria-labelledby="shor-title">
        <h2 id="shor-title">Shor's algorithm, honestly</h2>
        <Shor sh={shor} />
      </section>
      <Tooltip tip={tip} />
    </>
  );
}
