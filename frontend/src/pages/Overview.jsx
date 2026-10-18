import { useEffect, useMemo, useState } from "react";
import { api, download } from "../api.js";
import FleetMap from "../FleetMap.jsx";
import { Drawer, Empty, PageHead, Pill, SEVERITY, STATUS, Status, ago, groupName, plural, tone, when } from "../ui.jsx";

const blocked = (s) => /upgrade first/.test(s.y_reason || "");

const KIND = { nginx: "nginx", apache: "Apache", haproxy: "HAProxy", caddy: "Caddy", postfix: "Postfix", dovecot: "Dovecot", sshd: "OpenSSH" };

function Risk({ s }) {
  const sev = SEVERITY[s.severity] || SEVERITY.unknown;
  return (
    <div>
      <Pill tone={sev.tone}>{sev.label}</Pill>
      {s.at_risk && s.margin != null && <div className="sub">Exposed by {s.margin.toFixed(1)} years</div>}
    </div>
  );
}

export default function Overview({ overview, z, setZ, perms, guard, toast, loadOverview }) {
  const [filter, setFilter] = useState(null);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(null);
  const [scanning, setScanning] = useState(false);

  const services = overview?.services || [];
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return services.filter(
      (s) => (!filter || tone(s.status) === filter) && (!needle || `${s.name} ${s.endpoint} ${s.data_category}`.toLowerCase().includes(needle)),
    );
  }, [services, filter, q]);
  const attention = services.filter((s) => s.at_risk).slice(0, 5);

  const rescan = () => guard(async () => {
    await api("/api/jobs", { method: "POST", body: { kind: "scan" } });
    setScanning(true);
    toast("Scan started. Results update when it finishes.");
  });
  useEffect(() => {
    if (!scanning) return undefined;
    const t = setInterval(async () => {
      const jobs = await guard(() => api("/api/jobs"));
      if (jobs && !jobs.some((j) => j.kind === "scan" && j.status === "running")) {
        setScanning(false);
        loadOverview();
        toast("Scan finished.");
      }
    }, 2000);
    return () => clearInterval(t);
  }, [scanning]); // eslint-disable-line react-hooks/exhaustive-deps

  const get = (path, file) => guard(() => download(path, file));

  if (!overview) return <PageHead title="Overview" />;
  const scan = overview.scan;

  return (
    <>
      <PageHead
        title="Overview"
        actions={
          scan && (
            <>
              <button type="button" className="btn" onClick={() => get(`/api/report.html?z=${z}`, "aegisq-report.html")}>Download report</button>
              <button type="button" className="btn" onClick={() => get("/api/cbom", "cbom.json")}>Download CBOM</button>
              {overview.can_rescan && (
                <button type="button" className="btn primary" onClick={rescan} disabled={scanning || !perms.has("run")}
                  title={perms.has("run") ? "" : "Your role can view results but not start scans"}>
                  {scanning ? "Scanning" : "Rescan"}
                </button>
              )}
            </>
          )
        }
      >
        {scan ? `Last scanned ${ago(scan.finished)}. Click a server for details.` : "No scan yet."}
      </PageHead>

      {!scan ? (
        <section className="panel">
          <Empty title="Nothing scanned yet">
            <p>Scan your servers to see which ones still use classical key exchange.</p>
            <p><a className="btn primary" href="#run">Start a scan</a></p>
          </Empty>
        </section>
      ) : (
        <>
          <section className="panel">
            <FleetMap services={services} filter={filter} onFilter={setFilter} onSelect={setOpen} />
            <div className="horizon">
              <label htmlFor="z">Quantum computer in</label>
              <input id="z" type="range" min={1} max={30} step={1} value={z ?? overview.z_default} onChange={(e) => setZ(Number(e.target.value))} />
              <output htmlFor="z">{plural(z ?? overview.z_default, "year")}</output>
              <span className="hint">
                Nobody knows the date. A server is exposed when its data must stay secret longer than this, minus the time
                to fix it.
              </span>
            </div>
          </section>

          {attention.length > 0 && (
            <section className="panel">
              <div className="panel-head">
                <div>
                  <h2>Needs attention</h2>
                  <p>Exposed to harvest-now, decrypt-later at {plural(z, "year")}, most urgent first.</p>
                </div>
              </div>
              <div className="table-wrap">
                <table className="data">
                  <tbody>
                    {attention.map((s) => (
                      <tr key={s.name} className="click" tabIndex={0} onClick={() => setOpen(s)} onKeyDown={(e) => e.key === "Enter" && setOpen(s)}>
                        <td><b>{s.name}</b><div className="sub">{s.endpoint}</div></td>
                        <td className="wrap ink2">{s.findings[0] || s.errors[0] || STATUS[s.status]?.label}</td>
                        <td><Risk s={s} /></td>
                        <td className="nowrap">
                          {!s.managed ? <span className="muted">Owner must change it</span>
                            : blocked(s) ? <span className="muted">Needs a software upgrade</span>
                              : <a href="#run" onClick={(e) => e.stopPropagation()}>Fix with the agent</a>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section className="panel">
            <div className="toolbar">
              <h2 className="sr-only">All servers</h2>
              <input className="input" type="search" placeholder="Search servers" aria-label="Search servers" value={q} onChange={(e) => setQ(e.target.value)} />
              <span className="muted">
                {rows.length === services.length ? plural(services.length, "server") : `${rows.length} of ${services.length} servers`}
                {filter && (
                  <> <button type="button" className="btn ghost small" onClick={() => setFilter(null)}>Clear filter</button></>
                )}
              </span>
            </div>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>Server</th><th>Status</th><th>Key exchange</th><th>Data</th><th>Risk</th><th>Changed by</th></tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.name} className="click" tabIndex={0} onClick={() => setOpen(s)} onKeyDown={(e) => e.key === "Enter" && setOpen(s)}>
                      <td><b>{s.name}</b><div className="sub">{s.endpoint}{s.starttls ? ` with STARTTLS` : ""}</div></td>
                      <td><Status status={s.status} /></td>
                      <td>{groupName(s.group) || <span className="muted">None</span>}</td>
                      <td>{s.data_category}</td>
                      <td><Risk s={s} /></td>
                      <td>{s.kind ? `AegisQ (${KIND[s.kind] || s.kind})` : <span className="muted">Owner</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!rows.length && <Empty title="No servers match">Try another search or clear the filter.</Empty>}
            </div>
          </section>
        </>
      )}
      {open && <ServerDrawer s={open} z={z} onClose={() => setOpen(null)} guard={guard} canRun={perms.has("run")} />}
    </>
  );
}

function OwnerBrief({ service, guard, canRun }) {
  const [b, setB] = useState(null);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    let live = true;
    api(`/api/brief/${encodeURIComponent(service)}`).then((r) => live && setB(r)).catch(() => {});
    return () => { live = false; };
  }, [service]);

  const write = (template) => guard(async () => {
    setBusy(template ? "template" : "gemma");
    setErr("");
    try {
      setB(await api("/api/brief", { method: "POST", body: { service, template } }));
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy("");
    }
  });

  return (
    <>
      <h3>Brief for the owner</h3>
      <p className="hint">
        Gemma 4 writes it from numbered facts. A sentence stays only if it cites facts that contain every version,
        name and number in it. The fix is vendor documentation, never model text.
      </p>
      {canRun && (
        <div className="row mt8">
          <button type="button" className="btn primary small" disabled={!!busy} onClick={() => write(false)}>
            {busy === "gemma" ? "Writing" : b ? "Rewrite with Gemma 4" : "Write with Gemma 4"}
          </button>
          <button type="button" className="btn small" disabled={!!busy} onClick={() => write(true)}>Facts only</button>
        </div>
      )}
      {err && <p className="hint risk-text mt8">{err}</p>}
      {b && (
        <div className="brief mt8">
          {b.sentences.map((x, i) => (
            <p key={i}>
              {x.text} {x.cites.map((c) => <span key={c} className="cite" title={b.facts[Number(c.slice(1)) - 1]}>{c}</span>)}
            </p>
          ))}
          {b.fix && <p className="brief-fix"><b>Fix</b> {b.fix}</p>}
          {b.removed.length > 0 && (
            <details>
              <summary>{plural(b.removed.length, "sentence")} removed by the fact check</summary>
              <ul className="findings">{b.removed.map((r, i) => <li key={i}><s>{r.text}</s> <span className="muted">({r.reason})</span></li>)}</ul>
            </details>
          )}
          <details>
            <summary>{plural(b.facts.length, "fact")}</summary>
            <ol className="findings">{b.facts.map((f, i) => <li key={i}>{f}</li>)}</ol>
          </details>
          <p className="hint">Written by {b.written_by}, {when(b.created_at)}</p>
        </div>
      )}
    </>
  );
}

function ServerDrawer({ s, z, onClose, guard, canRun }) {
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    guard(async () => {
      const rep = await api("/api/scan/latest");
      setDetail(rep?.results?.find((r) => r.service.name === s.name) || null);
    });
  }, [s.name]); // eslint-disable-line react-hooks/exhaustive-deps

  const tls = detail?.tls;
  const ssh = detail?.ssh;
  const cert = tls?.certificate;
  const versions = tls ? Object.entries(tls.supports || {}).filter(([, v]) => v).map(([k]) => k.replace("TLSv", "TLS ")).join(", ") : "";
  const sev = SEVERITY[s.severity] || SEVERITY.unknown;

  return (
    <Drawer title={s.name} sub={`${s.endpoint}, ${s.protocol.toUpperCase()}${s.starttls ? ` with STARTTLS (${s.starttls.toUpperCase()})` : ""}`} onClose={onClose}>
      <dl className="facts">
        <dt>Status</dt><dd><Status status={s.status} /></dd>
        <dt>Key exchange</dt><dd>{groupName(s.group) || "None negotiated"}</dd>
        {versions && <><dt>TLS versions</dt><dd>{versions}</dd></>}
        {ssh && <><dt>Software</dt><dd>{ssh.software || ssh.banner || "Unknown"}</dd></>}
        {cert && (
          <>
            <dt>Certificate</dt>
            <dd>
              {cert.subject}
              <div className="muted">{cert.key_type}{cert.key_size ? ` ${cert.key_size}-bit` : ""}{cert.curve ? ` ${cert.curve}` : ""}, expires {when(cert.not_after)}</div>
            </dd>
          </>
        )}
        <dt>Data</dt><dd>{s.data_category}</dd>
        {s.owner && <><dt>Owner</dt><dd>{s.owner}</dd></>}
        <dt>Changed by</dt><dd>{s.kind ? `AegisQ, with approval (${KIND[s.kind] || s.kind})` : s.platform ? `Owner (${s.platform})` : "Owner"}</dd>
      </dl>

      <h3>Risk at {z} years</h3>
      <div className="math">
        <div><b>{s.x}</b><span>years the data must stay secret</span></div>
        <div><b>{s.y}</b><span>years to fix ({s.y_reason})</span></div>
        <div><b>{z}</b><span>years until a quantum computer (your guess)</span></div>
      </div>
      <p className="hint mt8">
        {s.at_risk
          ? `${s.x} + ${s.y} is more than ${z}, so traffic recorded today could be read in time. ${sev.label} risk.`
          : s.status === "pq_ready"
            ? "This server already completes a post-quantum handshake."
            : `${s.x} + ${s.y} is not more than ${z}, so this server is not exposed under this guess.`}
      </p>

      {(s.findings.length > 0 || s.errors.length > 0) && (
        <>
          <h3>Findings</h3>
          <ul className="findings">
            {[...s.errors, ...s.findings].map((f) => <li key={f}>{f}</li>)}
          </ul>
        </>
      )}

      {s.status !== "pq_ready" && (
        <>
          <h3>What to do</h3>
          {s.kind && blocked(s) ? (
            <p className="ink2">The software on this server cannot use ML-KEM yet ({s.y_reason}). No config line can fix it.</p>
          ) : s.kind ? (
            <p className="ink2">AegisQ manages this server. Start a run with <b>Scan and fix</b> and approve the change it proposes. <a href="#run">Open Run</a></p>
          ) : (
            <p className="ink2">{s.advice}</p>
          )}
        </>
      )}

      <OwnerBrief service={s.name} guard={guard} canRun={canRun} />
    </Drawer>
  );
}
