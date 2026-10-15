import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import Header from "./Header.jsx";
import LiveLattice from "./LiveLattice.jsx";
import Results from "./Results.jsx";
import { AuthError, makeApi } from "../api.js";
import { SCANNED, follow, sleep } from "./shared.js";
import "./ui.css";

const OUT = [0.16, 1, 0.3, 1];
const STAGES = ["Scanning services", "Analysing handshakes", "Fix & verify", "Sealing audit chain"];
const PLANNERS = [["rules", "Rules"], ["local", "Gemma 4"], ["claude", "Claude"]];

function Toggle({ on, disabled, title, onClick, children }) {
  return (
    <button
      type="button"
      disabled={disabled}
      title={title}
      onClick={onClick}
      className={`text-sm transition-colors duration-300 disabled:cursor-not-allowed disabled:text-zinc-700 ${on ? "text-paper" : "text-zinc-500 hover:text-paper"}`}
    >
      <span className={`mr-2 inline-block h-1.5 w-1.5 rounded-full align-middle ${on ? "bg-paper" : "border border-zinc-600"}`} />
      {children}
    </button>
  );
}

function Label({ children }) {
  return <div className="mb-3 font-mono text-[10.5px] uppercase tracking-[0.2em] text-zinc-500">{children}</div>;
}

function Stage({ phase, skipFix }) {
  const label = phase === 2 && skipFix ? "Fix skipped · scan only" : STAGES[phase];
  return (
    <div className="pointer-events-none fixed bottom-6 left-6 z-10 flex items-baseline gap-4 font-mono text-[10.5px] sm:bottom-8 sm:left-10 sm:text-[11px]">
      <span className="tabular-nums text-paper">0{phase + 1}<span className="text-mute"> / 04</span></span>
      <span className="relative h-4 w-64 overflow-hidden">
        <AnimatePresence initial={false}>
          <motion.span
            key={label}
            initial={{ y: 12, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -12, opacity: 0 }}
            transition={{ duration: 0.6, ease: OUT }}
            className="absolute left-0 top-0 whitespace-nowrap text-mute"
          >
            {label}
          </motion.span>
        </AnimatePresence>
      </span>
    </div>
  );
}

function Approval({ a, onDecide, busy, who, perms }) {
  const canApprove = perms.has("approve");
  const own = !!(a.require_other && a.initiated_by && a.initiated_by.toLowerCase() === (who || "").toLowerCase());
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.6, ease: OUT }}
      className="fixed inset-x-6 bottom-20 z-20 border-t border-white/15 bg-ink pt-5 lg:inset-x-auto lg:bottom-auto lg:right-10 lg:top-28 lg:w-[380px] lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0"
    >
      <Label>Approval required</Label>
      <div className="text-lg text-paper">{a.service}</div>
      <div className="mt-1 text-sm text-mute">{a.summary}</div>
      <pre className="mt-4 max-h-[34vh] overflow-auto font-mono text-[11px] leading-5">
        {a.diff.split("\n").map((l, i) => (
          <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-paper" : "text-zinc-500"}>{l || " "}</div>
        ))}
      </pre>
      {canApprove && (
        <div className="mt-5 flex items-center gap-6">
          {!own && (
            <button
              type="button"
              disabled={busy}
              onClick={() => onDecide(a, true)}
              className="rounded-full bg-paper px-5 py-2 text-sm font-medium text-ink transition-opacity hover:opacity-85 disabled:opacity-40"
            >
              Approve
            </button>
          )}
          <button type="button" disabled={busy} onClick={() => onDecide(a, false)} className="text-sm text-zinc-400 transition-colors hover:text-paper disabled:opacity-40">
            Reject
          </button>
        </div>
      )}
      {(own || !canApprove) && (
        <div className="mt-5 border-l border-white/20 pl-4 text-[13px] leading-relaxed text-zinc-300">
          {own
            ? "You started this run, so another approver has to approve this change (separation of duties). It is waiting for them in Approvals; this run continues as soon as they decide."
            : "Waiting for an approver. This run continues as soon as someone with the approver role decides."}
        </div>
      )}
      <div className="mt-4 font-mono text-[10px] text-zinc-600">Applied, verified, and rolled back automatically if verification fails.</div>
    </motion.div>
  );
}

export default function Console({ token: saved, onSignIn, onSignOut }) {
  const [view, setView] = useState("boot");
  const cli = useMemo(() => (saved ? makeApi(saved) : null), [saved]);
  const [who, setWho] = useState("");
  const [perms, setPerms] = useState(() => new Set());
  const [caps, setCaps] = useState(null);
  const [error, setError] = useState("");
  const [token, setToken] = useState("");

  const [mode, setMode] = useState("inventory");
  const [targets, setTargets] = useState("");
  const [fix, setFix] = useState(false);
  const [planner, setPlanner] = useState("rules");

  const [phase, setPhase] = useState(0);
  const [nodes, setNodes] = useState([]);
  const [focus, setFocus] = useState(null);
  const [sealed, setSealed] = useState(false);
  const [logLine, setLogLine] = useState("");
  const [pending, setPending] = useState([]);
  const [deciding, setDeciding] = useState(false);
  const [result, setResult] = useState(null);

  const alive = useRef(true);
  const jobId = useRef(null);
  useEffect(() => () => { alive.current = false; }, []);

  useEffect(() => {
    document.body.classList.add("aq-dark");
    return () => document.body.classList.remove("aq-dark");
  }, []);

  const signOut = (msg = "") => {
    setCaps(null);
    setWho("");
    setError(msg);
    setView("connect");
    onSignOut(msg);
  };

  useEffect(() => {
    if (!cli) { setView("connect"); return; }
    let live = true;
    (async () => {
      try {
        const me = await cli.api("/api/me");
        const cp = await cli.api("/api/capabilities");
        if (!live) return;
        setWho(me.identity);
        setPerms(new Set(me.permissions || []));
        setCaps(cp);
        setMode(cp.inventory ? "inventory" : "custom");
        setError("");
        setView("setup");
      } catch (e) {
        if (!live) return;
        if (e instanceof AuthError) signOut("Your token was rejected.");
        else { setError(`Cannot reach AegisQ: ${e.message}`); setView("connect"); }
      }
    })();
    return () => { live = false; };
  }, [cli]);

  const signIn = async (t) => {
    try {
      await makeApi(t).api("/api/me");
      setError("");
      onSignIn(t);
    } catch (e) {
      setError(e instanceof AuthError ? "Token rejected." : `Cannot reach AegisQ: ${e.message}`);
    }
  };

  const managed = caps ? caps.services.filter((s) => s.managed) : [];
  const canFix = !!(caps && caps.inventory && managed.length && mode === "inventory");

  const markScanned = (lines) => {
    for (const line of lines) {
      setLogLine(line);
      const m = SCANNED.exec(line);
      if (!m) continue;
      const [, name, status] = m;
      setFocus(name);
      setNodes((ns) => {
        const out = ns.slice();
        let k = out.findIndex((n) => n.name === name);
        if (k < 0) k = out.findIndex((n) => !n.name);
        if (k < 0) { out.push({ name, status }); return out; }
        out[k] = { name, status };
        return out;
      });
    }
  };

  const finish = async (c, res, seq0) => {
    setPhase(3);
    setFocus(null);
    const [ver, tail] = await Promise.all([c.api("/api/audit/verify"), c.api("/api/audit?limit=500")]);
    res.audit = { ...ver, events: (tail || []).filter((e) => e.seq > seq0).sort((a, b) => a.seq - b.seq) };
    setSealed(true);
    await sleep(2400);
    res.finished = Date.now();
    return res;
  };

  const start = async () => {
    const c = cli;
    const useFix = fix && canFix;
    const lines = mode === "custom" ? targets.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")) : [];
    if (mode === "custom" && !lines.length) { setError("Enter at least one server."); return; }
    setError("");
    setPhase(0);
    setSealed(false);
    setFocus(null);
    setPending([]);
    setLogLine("Starting scan");
    setNodes(mode === "inventory" ? caps.services.map((s) => ({ name: s.name, status: null })) : lines.map(() => ({ name: null, status: null })));
    setView("running");

    const res = { started: Date.now(), who, mode, fix: useFix, planner };
    try {
      const last = await c.api("/api/audit?limit=1");
      const seq0 = last && last.length ? Math.max(...last.map((e) => e.seq)) : -1;

      const t0 = Date.now();
      const job = await c.api("/api/jobs", { method: "POST", body: JSON.stringify(mode === "custom" ? { kind: "scan", targets: lines.join("\n") } : { kind: "scan" }) });
      jobId.current = job.id;
      const order = [];
      const scan = await follow(c.api, job.id, (ls) => {
        for (const l of ls) { const m = SCANNED.exec(l); if (m) order.push({ name: m[1], status: m[2] }); }
        markScanned(ls);
      }, () => alive.current);
      jobId.current = null;
      res.scan = { status: scan.status, exit: scan.exit_code, lines: scan.lines, order, seconds: (Date.now() - t0) / 1000, label: scan.label };

      setPhase(1);
      setFocus(null);
      const ov = await c.api("/api/overview");
      res.analysis = ov;
      if (ov && ov.services && mode === "inventory") {
        setNodes((ns) => ns.map((n) => { const s = ov.services.find((x) => x.name === n.name); return s ? { ...n, status: s.status } : n; }));
      }
      setLogLine(ov && ov.scan ? `${ov.scan.summary.pq_ready} of ${ov.scan.summary.total} services complete a post-quantum handshake` : "No scan results");
      await sleep(2600);

      setPhase(2);
      if (useFix && scan.status === "succeeded") {
        const before = Object.fromEntries((ov?.services || []).map((s) => [s.name, s.status]));
        const t1 = Date.now();
        const mj = await c.api("/api/jobs", { method: "POST", body: JSON.stringify({ kind: "migrate", planner, services: [] }) });
        jobId.current = mj.id;
        let polling = true;
        (async () => {
          while (polling && alive.current) {
            try {
              const list = await c.api("/api/approvals?status=pending");
              const mine = (list || []).filter((a) => a.requested_at * 1000 >= res.started - 5000);
              setPending(mine);
              setFocus(mine.length ? mine[0].service : null);
            } catch {}
            await sleep(1200);
          }
        })();
        const mig = await follow(c.api, mj.id, markScanned, () => alive.current);
        polling = false;
        jobId.current = null;
        setPending([]);
        const [ov2, appr, tail] = await Promise.all([c.api("/api/overview"), c.api("/api/approvals"), c.api("/api/audit?limit=200&event=agent.")]);
        const fin = (tail || []).filter((e) => e.event === "agent.finished" && e.seq > seq0).pop();
        res.fix = {
          status: mig.status,
          exit: mig.exit_code,
          lines: mig.lines,
          seconds: (Date.now() - t1) / 1000,
          outcomes: fin ? fin.data.outcomes : {},
          approvals: (appr || []).filter((a) => a.requested_at * 1000 >= res.started - 5000),
          before,
          after: Object.fromEntries((ov2?.services || []).map((s) => [s.name, s.status])),
        };
        res.analysisAfter = ov2;
      } else {
        res.fix = null;
        await sleep(1400);
      }

      setResult(await finish(c, res, seq0));
      setView("results");
    } catch (e) {
      if (e instanceof AuthError) { signOut("Your token was rejected."); return; }
      res.error = e.message;
      res.finished = Date.now();
      setResult(res);
      setView("results");
    }
  };

  const latest = async () => {
    const c = cli;
    try {
      const [ov, ver, tail] = await Promise.all([c.api("/api/overview"), c.api("/api/audit/verify"), c.api("/api/audit?limit=40")]);
      setResult({
        started: ov?.scan ? Date.parse(ov.scan.finished) : Date.now(),
        finished: ov?.scan ? Date.parse(ov.scan.finished) : Date.now(),
        who,
        mode: "latest",
        scan: ov?.scan ? { status: "succeeded", lines: [], order: ov.services.map((s) => ({ name: s.name, status: s.status })), seconds: null } : null,
        analysis: ov,
        fix: null,
        audit: { ...ver, events: (tail || []).sort((a, b) => a.seq - b.seq) },
      });
      setView("results");
    } catch (e) {
      if (e instanceof AuthError) signOut("Your token was rejected.");
      else setError(e.message);
    }
  };

  const decide = async (a, approve) => {
    setDeciding(true);
    try {
      await cli.api(`/api/approvals/${encodeURIComponent(a.id)}/decision`, {
        method: "POST",
        body: JSON.stringify({ approve, reason: approve ? null : "Rejected from the AegisQ console" }),
      });
      setPending((p) => p.filter((x) => x.id !== a.id));
      setLogLine(`${approve ? "Approved" : "Rejected"} change for ${a.service}`);
    } catch (e) {
      setLogLine(e.message);
    }
    setDeciding(false);
  };

  const cancel = async () => {
    if (!jobId.current) return;
    try { await cli.api(`/api/jobs/${encodeURIComponent(jobId.current)}/cancel`, { method: "POST" }); setLogLine("Cancelling; unverified changes roll back"); } catch {}
  };

  const shell = (child) => (
    <div id="aq" className="relative min-h-[100svh] w-full">
      <Header active="console" signedIn={!!saved} showDashboard={view === "results"} />
      {child}
    </div>
  );

  if (view === "boot") return shell(null);

  if (view === "connect") {
    return (
      shell(
      <div className="flex min-h-[100svh] items-center justify-center px-6">
        <motion.form
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: OUT }}
          onSubmit={(e) => { e.preventDefault(); if (token.trim()) signIn(token.trim()); }}
          className="w-full max-w-sm"
        >
          <Label>Connect to AegisQ</Label>
          <input
            type="password"
            autoComplete="off"
            autoFocus
            placeholder="API token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="w-full border-0 border-b border-white/20 bg-transparent pb-3 text-lg text-paper outline-none transition-colors placeholder:text-zinc-600 focus:border-paper"
          />
          <div className="mt-6 flex items-center justify-between">
            <span className="font-mono text-[10.5px] text-zinc-600">Token from <span className="text-zinc-400">aegisq serve</span></span>
            <button type="submit" className="text-sm text-paper transition-opacity hover:opacity-70">Connect →</button>
          </div>
          <div className="mt-6 min-h-[1.25rem] font-mono text-[11px] text-zinc-400">{error}</div>
        </motion.form>
      </div>
      )
    );
  }

  if (view === "setup") {
    return (
      shell(
      <div className="flex min-h-[100svh] items-center justify-center px-6 py-28">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, ease: OUT }} className="w-full max-w-md">
          <div className="mb-12 flex items-baseline justify-between font-mono text-[10.5px] text-zinc-500">
            <span>Signed in as <span className="text-paper">{who}</span></span>
            <button type="button" onClick={() => signOut("")} className="transition-colors hover:text-paper">Sign out</button>
          </div>

          <Label>01 · Targets</Label>
          <div className="flex flex-wrap gap-x-8 gap-y-3">
            <Toggle on={mode === "inventory"} disabled={!caps.inventory} title={caps.inventory ? "" : "Start aegisq serve with --inventory FILE"} onClick={() => setMode("inventory")}>
              Inventory{caps.inventory ? ` · ${caps.services.length}` : ""}
            </Toggle>
            <Toggle on={mode === "custom"} onClick={() => { setMode("custom"); setFix(false); }}>Custom servers</Toggle>
          </div>
          <AnimatePresence initial={false}>
            {mode === "custom" && (
              <motion.textarea
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 132 }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.5, ease: OUT }}
                spellCheck={false}
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder={"cloudflare.com\ngithub.com:22 ssh\nmail.example.com:993 tls payments"}
                className="mt-5 w-full resize-none border-0 border-b border-white/20 bg-transparent font-mono text-[12.5px] leading-6 text-paper outline-none placeholder:text-zinc-700 focus:border-paper"
              />
            )}
          </AnimatePresence>

          <div className="mt-12">
            <Label>02 · Agent</Label>
            <div className="flex flex-wrap gap-x-8 gap-y-3">
              <Toggle on={!fix} onClick={() => setFix(false)}>Scan only</Toggle>
              <Toggle on={fix && canFix} disabled={!canFix} title={canFix ? "" : "Needs the inventory with managed services"} onClick={() => setFix(true)}>
                Scan + fix{managed.length ? ` · ${managed.length} managed` : ""}
              </Toggle>
            </div>
            <AnimatePresence initial={false}>
              {fix && canFix && (
                <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.4 }} className="mt-5 flex flex-wrap gap-x-8 gap-y-3 pl-4">
                  {PLANNERS.map(([id, label]) => {
                    const p = caps.planners[id];
                    return (
                      <Toggle key={id} on={planner === id} disabled={!p.ok} title={p.detail} onClick={() => setPlanner(id)}>
                        {label}
                      </Toggle>
                    );
                  })}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="mt-14 flex flex-wrap items-center gap-x-8 gap-y-4">
            <button
              type="button"
              disabled={!caps.jobs || !perms.has("run")}
              onClick={start}
              className="rounded-full bg-paper px-6 py-2.5 text-sm font-medium text-ink transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-30"
            >
              Start run →
            </button>
            <button type="button" onClick={latest} className="text-sm text-zinc-400 transition-colors hover:text-paper">
              View latest results
            </button>
          </div>
          <div className="mt-6 min-h-[1.25rem] font-mono text-[11px] text-zinc-400">
            {!caps.jobs
              ? "This server is read-only (--read-only): runs are disabled."
              : !perms.has("run")
                ? "Your role can view results but not start runs. Ask an admin for the operator role."
                : error}
          </div>
        </motion.div>
      </div>
      )
    );
  }

  if (view === "running") {
    return (
      shell(
      <div className="relative flex h-[100svh] items-center justify-center overflow-hidden">
        <LiveLattice nodes={nodes} phase={phase} focus={focus} sealed={sealed} />
        <AnimatePresence>
          {pending[0] && <Approval key={pending[0].id} a={pending[0]} onDecide={decide} busy={deciding} who={who} perms={perms} />}
        </AnimatePresence>
        <Stage phase={phase} skipFix={!(fix && canFix)} />
        <div className="pointer-events-none fixed bottom-6 right-6 z-10 max-w-[42vw] truncate text-right font-mono text-[11px] text-zinc-500 max-md:hidden sm:bottom-8 sm:right-10">
          {logLine}
        </div>
        {(phase === 0 || phase === 2) && !sealed && (
          <button type="button" onClick={cancel} className="fixed right-6 top-20 z-10 font-mono text-[10.5px] text-zinc-600 transition-colors hover:text-paper sm:right-10 sm:top-24">
            Cancel
          </button>
        )}
      </div>
      )
    );
  }

  return shell(<Results r={result} cli={cli} onAgain={() => { setResult(null); setView("setup"); }} />);
}
