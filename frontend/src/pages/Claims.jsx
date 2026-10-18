import { useEffect, useRef, useState } from "react";
import { api, download } from "../api.js";
import { Empty, PageHead, Panel, Pill, Status, ago, plural } from "../ui.jsx";

const VERDICT = {
  confirmed: ["Confirmed", "safe"],
  contradicted: ["Contradicted", "risk"],
  unverifiable: ["Unverifiable", "idle"],
};
const MAX_IMAGE = 5 * 1024 * 1024;

function claimText(e) {
  const g = e.groups?.length ? ` (${e.groups.slice(0, 4).join(", ")})` : "";
  if (e.pq_claimed === true) return `Post-quantum enabled${g}`;
  if (e.pq_claimed === false) return `Classical only${g}`;
  if (e.groups?.length) return `Groups listed${g}`;
  return "No key-exchange claim";
}

function label(e) {
  const host = e.host.includes(":") ? `[${e.host}]` : e.host;
  const port = e.port || (e.starttls ? { smtp: 25, imap: 143, pop3: 110 }[e.starttls] : e.protocol === "ssh" ? 22 : 443);
  return `${host}:${port}${e.starttls ? ` (${e.starttls})` : ""}`;
}

export default function Claims({ me, perms, guard, toast, loadChain }) {
  const [caps, setCaps] = useState(null);
  const [text, setText] = useState("");
  const [image, setImage] = useState(null); // {name, dataUrl}
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [ext, setExt] = useState(null);
  const [picked, setPicked] = useState(new Set());
  const [history, setHistory] = useState([]);
  const file = useRef(null);

  const loadHistory = () => guard(async () => setHistory((await api("/api/claims")) || []));
  useEffect(() => {
    guard(async () => setCaps(await api("/api/capabilities")));
    loadHistory();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const pickImage = (f) => {
    setError("");
    if (!f) { setImage(null); return; }
    if (!["image/png", "image/jpeg", "image/webp"].includes(f.type)) { setError("Choose a PNG, JPEG or WebP image."); return; }
    if (f.size > MAX_IMAGE) { setError("The image is larger than 5 MB."); return; }
    const r = new FileReader();
    r.onload = () => setImage({ name: f.name, dataUrl: r.result });
    r.readAsDataURL(f);
  };

  const read = async () => {
    if (!text.trim() && !image) { setError("Paste a config or choose a screenshot."); return; }
    setError(""); setBusy("read"); setExt(null);
    try {
      await guard(async () => {
        const out = await api("/api/claims", { method: "POST", body: { text: text.trim() || null, image: image?.dataUrl || null } });
        setExt(out);
        setPicked(new Set());
        loadHistory();
      });
    } finally { setBusy(""); }
  };

  const verify = async () => {
    setBusy("verify");
    try {
      await guard(async () => {
        const out = await api(`/api/claims/${encodeURIComponent(ext.id)}/verify`, { method: "POST", body: { endpoints: [...picked] } });
        setExt(out);
        loadHistory();
        loadChain();
        const n = out.checks.filter((c) => c.verdict === "contradicted").length;
        toast(n ? `${plural(n, "claim")} contradicted by the server` : "Checked every picked endpoint");
      });
    } finally { setBusy(""); }
  };

  const open = (id) => guard(async () => { const out = await api(`/api/claims/${encodeURIComponent(id)}`); if (out) { setExt(out); setPicked(new Set()); } });
  const toggle = (i) => setPicked((s) => { const n = new Set(s); if (n.has(i)) n.delete(i); else n.add(i); return n; });

  const gemma = caps?.planners?.gemma;
  const canRun = caps?.jobs && perms.has("run");

  return (
    <>
      <PageHead title="Check a claim">
        Share a config, command output or a screenshot of a console. Gemma 4 lists the servers and what it says about their key
        exchange. AegisQ then tests each server you pick with a real handshake. The model never decides the result.
      </PageHead>
      <div className="grid-run">
        <Panel title="What to check" sub={gemma ? (gemma.ok ? `Reads with ${gemma.detail}` : `Gemma 4 is not set up: ${gemma.detail}`) : ""}>
          <div className="form">
            <label className="field">
              <span>Config or command output</span>
              <textarea className="textarea" rows={8} spellCheck={false} value={text} disabled={!!busy}
                placeholder={"tls_eecdh_auto_curves = X25519MLKEM768, X25519\nmyhostname = mail.example.com"}
                onChange={(e) => setText(e.target.value)} />
            </label>
            <div className="field">
              <span>Screenshot</span>
              <div className="row">
                <button type="button" className="btn" disabled={!!busy} onClick={() => file.current?.click()}>{image ? "Replace image" : "Choose image"}</button>
                {image && <button type="button" className="btn ghost" disabled={!!busy} onClick={() => { setImage(null); if (file.current) file.current.value = ""; }}>Remove</button>}
                <input ref={file} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => pickImage(e.target.files?.[0])} />
              </div>
              {image && <img className="shot" src={image.dataUrl} alt={`Screenshot ${image.name}`} />}
              <small>PNG, JPEG or WebP, up to 5 MB. A TLS policy page, load balancer settings or nginx -V output work well.</small>
            </div>
            {error && <p className="error" role="alert">{error}</p>}
            {!canRun && caps && <p className="hint">{caps.jobs ? `Your role (${me.role}) can view checks but not start them.` : "This dashboard is read-only."}</p>}
            <div className="row">
              <button type="button" className="btn primary" onClick={read} disabled={!canRun || !gemma?.ok || !!busy}>
                {busy === "read" ? "Gemma 4 is reading" : "Read with Gemma 4"}
              </button>
            </div>
          </div>
        </Panel>

        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>{ext ? `What Gemma 4 read (${ext.model})` : "Result"}</h2>
              {ext && <p>{plural(ext.endpoints.length, "server")} found{ext.notes ? `. ${ext.notes}` : ""}</p>}
            </div>
            {ext?.scan_file && (
              <div className="actions">
                <button type="button" className="btn small" onClick={() => guard(() => download(`/api/claims/${encodeURIComponent(ext.id)}/cbom`, `cbom-${ext.id}.json`))}>Download CBOM</button>
              </div>
            )}
          </div>
          {!ext && <Empty title="Nothing checked yet">Paste a config or choose a screenshot, then read it with Gemma 4.</Empty>}
          {ext && !ext.checks && (
            ext.endpoints.length ? (
              <div className="panel-body">
                <fieldset className="checks" disabled={!!busy}>
                  <legend className="field"><span>Pick the servers you own to test</span></legend>
                  {ext.endpoints.map((e, i) => (
                    <label key={i} className="choice-item">
                      <input type="checkbox" checked={picked.has(i)} onChange={() => toggle(i)} />
                      <span>
                        <b>{label(e)}</b>
                        <small>{claimText(e)}{e.platform ? `, ${e.platform}` : ""}</small>
                        {e.evidence && <small className="block">“{e.evidence}”</small>}
                        {e.grounded === false && <Pill tone="warn">Not found in your text</Pill>}
                      </span>
                    </label>
                  ))}
                </fieldset>
                {ext.dropped?.length > 0 && <p className="hint mt8">Ignored: {ext.dropped.join("; ")}</p>}
                <div className="row mt16">
                  <button type="button" className="btn primary" disabled={!picked.size || !!busy || !canRun} onClick={verify}>
                    {busy === "verify" ? "Testing" : `Test ${plural(picked.size, "server")}`}
                  </button>
                  <span className="hint">Handshakes only. Nothing on the servers changes.</span>
                </div>
              </div>
            ) : <Empty title="No servers found">{ext.notes || "Gemma 4 did not find an endpoint in what you shared."}</Empty>
          )}
          {ext?.checks && (
            <div className="panel-body">
              <div className="verdicts">
                {Object.entries(VERDICT).map(([k, [l, t]]) => (
                  <div key={k} className="verdict-stat">
                    <span className="stat">{ext.checks.filter((c) => c.verdict === k).length}</span>
                    <Pill tone={t}>{l}</Pill>
                  </div>
                ))}
              </div>
              <p className="hint mt16">Every verdict comes from a handshake with the server, not from the model. Fixes come from vendor documentation.</p>
            </div>
          )}
        </section>
      </div>

      {ext?.checks && (
        <Panel title="Claim against handshake" sub="What Gemma 4 read, what the server actually did, and the verdict" flush className="mt16">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Server</th><th>Gemma read</th><th>The server did</th><th>Verdict</th><th>Fix</th></tr></thead>
              <tbody>
                {ext.checks.map((c) => {
                  const [l, t] = VERDICT[c.verdict];
                  return (
                    <tr key={c.index}>
                      <td className="nowrap"><b>{c.endpoint}</b><div><Status status={c.status} /></div></td>
                      <td className="wrap">{c.claim}{c.grounded === false && <div className="mt8"><Pill tone="warn">Not found in your text</Pill></div>}</td>
                      <td className="wrap">{c.observed}{c.unverified && <div className="muted">{c.unverified}</div>}</td>
                      <td className="wrap"><Pill tone={t}>{l}</Pill><div className="muted mt8">{c.reason}</div></td>
                      <td className="wrap">{c.fix || <span className="muted">Nothing to change</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {history.length > 0 && (
        <Panel title="Recent checks" flush className="mt16">
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>When</th><th>By</th><th>Source</th><th>Servers</th><th>Result</th></tr></thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="click" tabIndex={0} onClick={() => open(h.id)} onKeyDown={(k) => k.key === "Enter" && open(h.id)}>
                    <td className="nowrap">{ago(h.created_at)}</td>
                    <td>{h.created_by}</td>
                    <td>{h.source.replace("+", " and ")}</td>
                    <td className="num">{h.endpoints}</td>
                    <td>{h.summary ? `${h.summary.confirmed} confirmed, ${h.summary.contradicted} contradicted, ${h.summary.unverifiable} unverifiable` : <span className="muted">Not tested</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </>
  );
}
