import { useState } from "react";
import { motion } from "framer-motion";
import { STATUS } from "./shared.js";

const OUT = [0.16, 1, 0.3, 1];
const DECISION = { consumed: "approved", approved: "approved", rejected: "rejected", expired: "expired", cancelled: "cancelled", pending: "pending" };

const yrs = (v) => `${Math.abs(v) % 1 ? Math.abs(v).toFixed(1) : Math.abs(v)} yr${Math.abs(v) === 1 ? "" : "s"}`;

function risk(s, z) {
  if (s.status === "pq_ready") return ["Protected", "text-paper"];
  if (s.status === "unreachable" || s.status === "error") return ["Unknown", "text-zinc-500"];
  const m = s.x + s.y - (s.status === "plaintext" ? 0 : z);
  return m > 0 ? [`Exposed by ${yrs(m)}`, "text-paper"] : [`${yrs(m)} to spare`, "text-zinc-400"];
}

function Dot({ status }) {
  if (status === "pq_ready") return <span className="inline-block h-2 w-2 rounded-full bg-paper" />;
  if (status === "classical" || status === "tls12_only") return <span className="inline-block h-2 w-2 rounded-full border border-paper" />;
  if (status === "legacy_tls" || status === "plaintext") return <span className="inline-block h-2 w-2 rounded-full border border-dashed border-mute" />;
  return <span className="inline-block h-1.5 w-1.5 rounded-full border border-zinc-600" />;
}

function Output({ lines }) {
  const [open, setOpen] = useState(false);
  if (!lines || !lines.length) return null;
  return (
    <div className="mt-6">
      <button type="button" onClick={() => setOpen((o) => !o)} className="font-mono text-[10.5px] text-zinc-500 transition-colors hover:text-paper">
        {open ? "−" : "+"} Output · {lines.length} lines
      </button>
      {open && (
        <pre className="mt-3 max-h-80 overflow-auto border-l border-white/10 pl-4 font-mono text-[11px] leading-5 text-zinc-400">{lines.join("\n")}</pre>
      )}
    </div>
  );
}

function Step({ n, title, note, children, i }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8, delay: 0.15 + i * 0.12, ease: OUT }}
      className="grid gap-6 border-t border-white/10 py-12 md:grid-cols-[220px_1fr] md:gap-10"
    >
      <div>
        <div className="font-mono text-[11px] text-zinc-500">{n}</div>
        <h2 className="mt-2 text-lg text-paper">{title}</h2>
        {note && <p className="mt-2 text-[13px] leading-relaxed text-zinc-500">{note}</p>}
      </div>
      <div className="min-w-0">{children}</div>
    </motion.section>
  );
}

function Row({ cols }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1 border-b border-white/[0.06] py-3 text-[13px] sm:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1fr)]">
      {cols.map((c, k) => <div key={k} className={`min-w-0 ${k === 2 ? "col-span-2 sm:col-span-1" : ""}`}>{c}</div>)}
    </div>
  );
}

const Empty = ({ children }) => <p className="text-[13px] text-zinc-500">{children}</p>;

export default function Results({ r, cli, onAgain }) {
  const [msg, setMsg] = useState("");
  const [allEvents, setAllEvents] = useState(false);
  const ov = r.analysisAfter || r.analysis;
  const sm = ov && ov.scan ? ov.scan.summary : null;
  const reach = sm ? sm.total - sm.unreachable - sm.error : 0;
  const z = r.analysis ? r.analysis.z_default : 10;
  const byName = Object.fromEntries((r.analysis?.services || []).map((s) => [s.name, s]));
  const secs = Math.max(0, (r.finished - r.started) / 1000);
  const when = new Date(r.started).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  const fixNames = r.fix ? Array.from(new Set([...Object.keys(r.fix.outcomes), ...r.fix.approvals.map((a) => a.service)])) : [];

  const dl = async (path, name) => {
    try { setMsg(""); await cli.download(path, name); } catch (e) { setMsg(e.message); }
  };

  return (
    <div className="mx-auto w-full max-w-5xl px-6 pb-24 pt-32 sm:px-10 sm:pt-40">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: OUT }}>
        <div className="font-mono text-[10.5px] uppercase tracking-[0.2em] text-zinc-500">
          {r.error ? "Run stopped" : r.mode === "latest" ? "Latest results" : "Run complete"}
        </div>
        <h1 className="mt-5 max-w-3xl text-3xl font-light leading-tight tracking-tight text-paper sm:text-[2.6rem]">
          {r.error
            ? r.error
            : sm
              ? `${sm.pq_ready} of ${reach || sm.total} reachable services complete a post-quantum handshake.`
              : "No scan results yet."}
        </h1>
        <div className="mt-5 font-mono text-[11px] text-zinc-500">
          {when}{r.mode !== "latest" ? ` · ${secs.toFixed(1)} s` : ""} · {r.who}
          {r.audit ? ` · audit ${r.audit.ok ? "intact" : "TAMPERED"}` : ""}
        </div>
        <div className="mt-8 flex flex-wrap items-center gap-x-8 gap-y-3 text-sm">
          <button type="button" onClick={onAgain} className="rounded-full bg-paper px-5 py-2 font-medium text-ink transition-opacity hover:opacity-85">New run</button>
          <button type="button" onClick={() => dl("/api/report.html", "aegisq-report.html")} className="text-zinc-400 transition-colors hover:text-paper">Report ↓</button>
          <button type="button" onClick={() => dl("/api/cbom", "cbom.json")} className="text-zinc-400 transition-colors hover:text-paper">CBOM ↓</button>
          <span className="font-mono text-[11px] text-zinc-500">{msg}</span>
        </div>
      </motion.div>

      <div className="mt-16">
        <Step i={0} n="01" title="Scan" note={r.scan ? `${r.scan.label || "Scan"} · ${r.scan.status}${r.scan.seconds ? ` · ${r.scan.seconds.toFixed(1)} s` : ""}` : null}>
          {r.scan && r.scan.order.length ? (
            r.scan.order.map((o, k) => (
              <Row
                key={`${o.name}-${k}`}
                cols={[
                  <span className="text-paper" key="n">{o.name}</span>,
                  <span className="font-mono text-[11.5px] text-zinc-500" key="e">{byName[o.name] ? `${byName[o.name].endpoint} · ${byName[o.name].protocol}` : "—"}</span>,
                  <span className="flex items-center gap-2.5 text-zinc-300" key="s"><Dot status={o.status} />{STATUS[o.status] || o.status}</span>,
                ]}
              />
            ))
          ) : (
            <Empty>No services were scanned.</Empty>
          )}
          <Output lines={r.scan?.lines} />
        </Step>

        <Step i={1} n="02" title="Handshake analysis" note={`Mosca margin X + Y − Z with Z = ${z} years. Positive means data is already exposed to harvest-now, decrypt-later.`}>
          {r.analysis && r.analysis.services.length ? (
            r.analysis.services.map((s) => {
              const [label, cls] = risk(s, z);
              return (
                <Row
                  key={s.name}
                  cols={[
                    <span key="n"><span className="text-paper">{s.name}</span><span className="ml-2 font-mono text-[10.5px] text-zinc-600">#{s.rank}</span></span>,
                    <span className="text-zinc-400" key="f">{s.findings[0] || s.errors[0] || STATUS[s.status]}</span>,
                    <span className={cls} key="r">{label}<span className="ml-2 font-mono text-[10.5px] text-zinc-600">{s.data_category}</span></span>,
                  ]}
                />
              );
            })
          ) : (
            <Empty>No handshake results.</Empty>
          )}
        </Step>

        <Step i={2} n="03" title="Fix & verify" note={r.fix ? `${r.planner} planner · ${r.fix.status} · ${r.fix.seconds.toFixed(1)} s` : "Each change is approved by a person, applied, re-verified with a fresh handshake, and rolled back on failure."}>
          {!r.fix ? (
            <Empty>{r.mode === "latest" ? "Not part of this view." : "Skipped. This was a scan-only run; choose Scan + fix to let the agent propose changes."}</Empty>
          ) : fixNames.length ? (
            fixNames.map((name) => {
              const a = r.fix.approvals.filter((x) => x.service === name).pop();
              const before = r.fix.before[name];
              const after = r.fix.after[name];
              return (
                <Row
                  key={name}
                  cols={[
                    <span key="n"><span className="text-paper">{name}</span><span className="ml-2 text-zinc-500">{(r.fix.outcomes[name] || "—").replace(/_/g, " ")}</span></span>,
                    <span className="flex items-center gap-2 text-zinc-400" key="d">
                      <Dot status={before} />{STATUS[before] || "—"}<span className="text-zinc-600">→</span><Dot status={after} />{STATUS[after] || "—"}
                    </span>,
                    <span className="text-zinc-500" key="a">{a ? `${DECISION[a.status] || a.status}${a.decided_by ? ` by ${a.decided_by}` : ""}` : "no approval requested"}</span>,
                  ]}
                />
              );
            })
          ) : (
            <Empty>The agent found nothing it was allowed to change.</Empty>
          )}
          <Output lines={r.fix?.lines} />
        </Step>

        <Step i={3} n="04" title="Audit" note={r.audit ? `${r.audit.keyed ? "HMAC" : "SHA-256"} hash chain · ${r.audit.entries} entries` : null}>
          {r.audit ? (
            <>
              <p className="mb-4 text-[13px] text-paper">{r.audit.ok ? "Chain verified intact. Every event below is sealed to the one before it." : `Chain broken: ${r.audit.error}`}</p>
              {(allEvents ? r.audit.events : r.audit.events.slice(-12)).map((e) => (
                <Row
                  key={e.seq}
                  cols={[
                    <span className="font-mono text-[11.5px] text-zinc-500" key="t">#{e.seq} · {new Date(e.ts).toLocaleTimeString()}</span>,
                    <span className="text-paper" key="e">{e.event}</span>,
                    <span className="truncate font-mono text-[11px] text-zinc-500" key="h" title={e.hash}>{e.actor} · {String(e.hash).slice(0, 12)}…</span>,
                  ]}
                />
              ))}
              {r.audit.events.length > 12 && (
                <button type="button" onClick={() => setAllEvents((v) => !v)} className="mt-6 font-mono text-[10.5px] text-zinc-500 transition-colors hover:text-paper">
                  {allEvents ? "− Show last 12" : `+ Show all ${r.audit.events.length} events`}
                </button>
              )}
            </>
          ) : (
            <Empty>Audit not reached.</Empty>
          )}
        </Step>
      </div>
    </div>
  );
}
