import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AuthError, loadToken, makeApi, saveToken, startJob } from "./api.js";
import Login from "./Login.jsx";
import Overview from "./Overview.jsx";
import Run from "./Run.jsx";
import Approvals from "./Approvals.jsx";
import Measure from "./Measure.jsx";
import Audit from "./Audit.jsx";

const TABS = [
  ["overview", "Overview"], ["run", "Run"], ["approvals", "Approvals"], ["measure", "Measurements"], ["audit", "Audit log"],
];
const TAB_OF = { "": "overview", overview: "overview", top: "overview", risk: "overview", run: "run", approvals: "approvals", measure: "measure", audit: "audit" };

function useHashTab() {
  const read = () => TAB_OF[location.hash.replace(/^#/, "")] || "overview";
  const [tab, setTab] = useState(read);
  useEffect(() => {
    const on = () => { setTab(read()); window.scrollTo({ top: 0 }); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return tab;
}

export default function App() {
  const [token, setToken] = useState(loadToken);
  const [who, setWho] = useState(null);
  const [loginError, setLoginError] = useState("");

  const signOut = useCallback((msg = "") => {
    saveToken(null); setToken(null); setWho(null); setLoginError(msg);
  }, []);

  const client = useMemo(() => (token ? makeApi(token) : null), [token]);

  useEffect(() => {
    if (!client) return;
    let live = true;
    client.api("/api/me")
      .then((me) => { if (live) setWho(me.identity); })
      .catch((e) => { if (live) signOut(e instanceof AuthError ? "Invalid token." : `Cannot reach AegisQ: ${e.message}`); });
    return () => { live = false; };
  }, [client, signOut]);

  const signIn = (t) => { saveToken(t); setLoginError(""); setToken(t); };

  useEffect(() => { document.body.classList.toggle("signed-out", !who); }, [who]);

  if (!client || !who) {
    return (
      <>
        <NavShell />
        <Login onSubmit={signIn} error={loginError} />
      </>
    );
  }
  return <Dashboard client={client} who={who} signOut={signOut} />;
}

function NavShell({ children }) {
  return (
    <div className="nav-wrap">
      <header className="nav" aria-label="AegisQ">
        <a className="wordmark" href="#overview" aria-label="AegisQ home">AEGIS<span>Q</span></a>
        {children}
      </header>
    </div>
  );
}

function Dashboard({ client, who, signOut }) {
  const tab = useHashTab();
  const [z, setZ] = useState(10);
  const [overview, setOverview] = useState(null);
  const [approvals, setApprovals] = useState([]);
  const [audit, setAudit] = useState({ rows: [], verify: null });
  const [caps, setCaps] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [extras, setExtras] = useState({ realworld: null, benchmark: null });
  const seen = useRef({});
  const zSet = useRef(false);

  const guarded = useCallback(async (fn) => {
    try { await fn(); } catch (e) {
      if (e instanceof AuthError) signOut("Your token was rejected.");
      else console.error(e);
    }
  }, [signOut]);

  const loadOverview = useCallback(() => guarded(async () => {
    const ov = await client.api("/api/overview");
    if (!ov) return;
    if (!zSet.current) { setZ(ov.z_default); zSet.current = true; }
    setOverview(ov);
  }), [client, guarded]);

  const loadApprovals = useCallback(() => guarded(async () => setApprovals((await client.api("/api/approvals")) || [])), [client, guarded]);

  const loadAudit = useCallback(() => guarded(async () => {
    const [rows, verify] = await Promise.all([client.api("/api/audit?limit=60"), client.api("/api/audit/verify")]);
    setAudit({ rows: rows || [], verify });
  }), [client, guarded]);

  const loadExtras = useCallback(() => guarded(async () => {
    const [realworld, benchmark] = await Promise.all([client.api("/api/realworld"), client.api("/api/benchmark")]);
    setExtras({ realworld, benchmark });
  }), [client, guarded]);

  const refreshResults = useCallback(() => {
    loadOverview(); loadExtras(); loadAudit(); loadApprovals();
  }, [loadOverview, loadExtras, loadAudit, loadApprovals]);

  const loadJobs = useCallback(() => guarded(async () => {
    const list = (await client.api("/api/jobs")) || [];
    let finished = false;
    for (const j of list) {
      if (seen.current[j.id] === "running" && j.status !== "running") finished = true;
      seen.current[j.id] = j.status;
    }
    setJobs(list);
    if (finished) refreshResults();
  }), [client, guarded, refreshResults]);

  useEffect(() => {
    loadOverview().then(() => {
      guarded(async () => setCaps(await client.api("/api/capabilities")));
      loadJobs(); loadApprovals(); loadAudit(); loadExtras();
    });
    const t = [
      setInterval(loadJobs, 3000),
      setInterval(loadApprovals, 3000),
      setInterval(loadAudit, 5000),
      setInterval(loadOverview, 15000),
    ];
    return () => t.forEach(clearInterval);
  }, [client, guarded, loadOverview, loadJobs, loadApprovals, loadAudit, loadExtras]);

  const pending = approvals.filter((a) => a.status === "pending");
  const ver = audit.verify;
  const auditKind = ver && ver.ok ? "good" : "critical";
  const auditText = ver ? (ver.ok ? `audit intact · ${ver.entries}` : "audit TAMPERED") : "audit …";

  return (
    <>
      <NavShell>
        <nav className="nav-links" aria-label="Sections">
          {TABS.map(([id, label]) => (
            <a key={id} href={`#${id}`} aria-current={tab === id ? "page" : undefined}>
              {label}
              {id === "approvals" && pending.length > 0 && <> <span className="count">{pending.length}</span></>}
            </a>
          ))}
        </nav>
        <div className="nav-right">
          <span className="nav-who">{who}</span>
          <span className={`badge badge-dark s-${auditKind}`} title={ver && !ver.ok ? ver.error : `${ver ? (ver.keyed ? "HMAC" : "SHA-256") : ""} hash chain`}>{auditText}</span>
          <button className="link-btn" type="button" onClick={() => signOut("")}>Sign out</button>
          <a className="button pill" href="#" onClick={(e) => { e.preventDefault(); client.download(`/api/report.html?z=${z}`, "aegisq-report.html"); }}>Get the report</a>
        </div>
      </NavShell>
      <main id="app">
        {tab === "overview" && (
          <Overview overview={overview} z={z} setZ={setZ} client={client}
            onRescan={() => startJob(client, { kind: "scan" }, loadJobs, signOut)} />
        )}
        {tab === "run" && (
          <Run client={client} caps={caps} jobs={jobs} pending={pending} loadJobs={loadJobs} signOut={signOut} />
        )}
        {tab === "approvals" && <Approvals client={client} approvals={approvals} reload={loadApprovals} />}
        {tab === "measure" && <Measure realworld={extras.realworld} benchmark={extras.benchmark} />}
        {tab === "audit" && <Audit rows={audit.rows} />}
      </main>
    </>
  );
}
