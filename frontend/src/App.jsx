import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AuthError, loadToken, makeApi, saveToken, startJob } from "./api.js";
import Login from "./Login.jsx";
import Overview from "./Overview.jsx";
import Approvals from "./Approvals.jsx";
import Measure from "./Measure.jsx";
import Settings from "./Settings.jsx";
import Audit from "./Audit.jsx";
import Landing from "./aq/Landing.jsx";
import Console from "./aq/Console.jsx";

const TABS = [
  ["overview", "Overview"], ["approvals", "Approvals"], ["measure", "Performance"], ["audit", "Audit log"],
];
const TAB_OF = { "": "overview", overview: "overview", top: "overview", risk: "overview", approvals: "approvals", measure: "measure", audit: "audit", settings: "settings" };

function useHash() {
  const read = () => location.hash.replace(/^#/, "");
  const [hash, setHash] = useState(read);
  useEffect(() => {
    const on = () => setHash(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

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
  const [me, setMe] = useState(null);
  const who = me ? me.identity : null;
  const [loginError, setLoginError] = useState("");
  const hash = useHash();

  const signOut = useCallback((msg = "") => {
    saveToken(null); setToken(null); setMe(null); setLoginError(msg);
  }, []);

  const client = useMemo(() => (token ? makeApi(token) : null), [token]);

  useEffect(() => {
    if (!client) return;
    let live = true;
    client.api("/api/me")
      .then((m) => { if (live) setMe(m); })
      .catch((e) => { if (live) signOut(e instanceof AuthError ? "Invalid token." : `Cannot reach AegisQ: ${e.message}`); });
    return () => { live = false; };
  }, [client, signOut]);

  const signIn = (t) => { saveToken(t); setLoginError(""); setToken(t); };

  useEffect(() => { document.body.classList.toggle("signed-out", !who); }, [who]);

  if (hash === "intro") return <Landing signedIn={!!who} />;
  if (hash === "console" || hash === "run") {
    return <Console token={token} onSignIn={signIn} onSignOut={(msg) => signOut(msg)} />;
  }
  if (!client || !who) {
    if (hash !== "signin" && !loginError && !token) return <Landing signedIn={false} />;
    return (
      <>
        <NavShell />
        <Login onSubmit={signIn} error={loginError} />
      </>
    );
  }
  return <Dashboard client={client} me={me} signOut={signOut} />;
}

function NavShell({ children }) {
  return (
    <div className="nav-wrap">
      <header className="nav" aria-label="AegisQ">
        <a className="wordmark" href="#intro" aria-label="AegisQ intro">AEGIS<span>Q</span></a>
        {children}
      </header>
    </div>
  );
}

function Dashboard({ client, me, signOut }) {
  const who = me.identity;
  const perms = new Set(me.permissions || []);
  const tabs = perms.has("admin") ? [...TABS, ["settings", "Settings"]] : TABS;
  const tab = useHashTab();
  const [z, setZ] = useState(10);
  const [overview, setOverview] = useState(null);
  const [approvals, setApprovals] = useState([]);
  const [audit, setAudit] = useState({ rows: [], verify: null });
  const [jobs, setJobs] = useState([]);
  const [benchmark, setBenchmark] = useState(null);
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

  const loadExtras = useCallback(() => guarded(async () => setBenchmark(await client.api("/api/benchmark"))), [client, guarded]);

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
          {tabs.slice(0, 1).map(([id, label]) => (
            <a key={id} href={`#${id}`} aria-current={tab === id ? "page" : undefined}>{label}</a>
          ))}
          <a href="#console">Run</a>
          {tabs.slice(1).map(([id, label]) => (
            <a key={id} href={`#${id}`} aria-current={tab === id ? "page" : undefined}>
              {label}
              {id === "approvals" && pending.length > 0 && <> <span className="count">{pending.length}</span></>}
            </a>
          ))}
        </nav>
        <div className="nav-right">
          <span className="nav-who" title={`permissions: ${[...perms].join(", ")}`}>{who} · {me.role}</span>
          <span className={`badge badge-dark s-${auditKind}`} title={ver && !ver.ok ? ver.error : `${ver ? (ver.keyed ? "HMAC" : "SHA-256") : ""} hash chain`}>{auditText}</span>
          <button className="link-btn" type="button" onClick={() => signOut("")}>Sign out</button>
          <a className="button pill" href="#" onClick={(e) => { e.preventDefault(); client.download(`/api/report.html?z=${z}`, "aegisq-report.html"); }}>Get the report</a>
        </div>
      </NavShell>
      <main id="app">
        {tab === "overview" && (
          <Overview overview={overview} z={z} setZ={setZ} client={client} canRun={perms.has("run")}
            onRescan={() => startJob(client, { kind: "scan" }, loadJobs, signOut)} />
        )}
        {tab === "approvals" && <Approvals client={client} approvals={approvals} reload={loadApprovals} me={me} />}
        {tab === "measure" && <Measure benchmark={benchmark} client={client} jobs={jobs} loadJobs={loadJobs} signOut={signOut} canRun={perms.has("run")} />}
        {tab === "settings" && perms.has("admin") && <Settings client={client} me={me} />}
        {tab === "audit" && <Audit rows={audit.rows} />}
      </main>
    </>
  );
}
