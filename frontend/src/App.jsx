import { useCallback, useEffect, useRef, useState } from "react";
import { AuthError, api } from "./api.js";
import { useTheme } from "./theme.js";
import { Mark, useToast } from "./ui.jsx";
import Landing from "./home/Landing.jsx";
import SignIn from "./pages/SignIn.jsx";
import Overview from "./pages/Overview.jsx";
import Run from "./pages/Run.jsx";
import Claims from "./pages/Claims.jsx";
import Approvals from "./pages/Approvals.jsx";
import Performance from "./pages/Performance.jsx";
import Audit from "./pages/Audit.jsx";
import Settings from "./pages/Settings.jsx";

const PAGES = ["overview", "run", "claims", "approvals", "performance", "audit", "settings"];

function useHash() {
  const read = () => location.hash.replace(/^#\/?/, "");
  const [hash, setHash] = useState(read);
  useEffect(() => {
    const on = () => { setHash(read()); window.scrollTo({ top: 0 }); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

export default function App() {
  const [theme, setTheme] = useTheme();
  const hash = useHash();
  const [me, setMe] = useState(undefined); // undefined: checking; null: signed out

  const refreshMe = useCallback(async () => {
    try { setMe(await api("/api/me")); } catch { setMe(null); }
  }, []);
  useEffect(() => { refreshMe(); }, [refreshMe]);

  const signOut = useCallback(async () => {
    try { await api("/api/logout", { method: "POST" }); } catch { /* already signed out */ }
    setMe(null);
    location.hash = "#signin";
  }, []);
  const expired = useCallback(() => { setMe(null); location.hash = "#signin"; }, []);

  if (me === undefined) return null;
  const page = hash.split("/")[0];
  if (page === "intro" || (page === "" && !me)) return <Landing signedIn={!!me} />;
  if (!me) return <SignIn onSignedIn={(m) => { setMe(m); location.hash = "#overview"; }} />;
  if (page === "signin") { location.hash = "#overview"; return null; }
  return <Shell me={me} hash={hash} theme={theme} setTheme={setTheme} signOut={signOut} expired={expired} />;
}

function Shell({ me, hash, theme, setTheme, signOut, expired }) {
  const [page, sub] = hash.split("/");
  const current = PAGES.includes(page) ? page : "overview";
  const perms = new Set(me.permissions || []);
  const [overview, setOverview] = useState(null);
  const [z, setZ] = useState(null);
  const [approvals, setApprovals] = useState([]);
  const [chain, setChain] = useState(null);
  const [menu, setMenu] = useState(false);
  const [toast, toastNode] = useToast();
  const zRef = useRef(null);
  zRef.current = z;

  const guard = useCallback(async (fn) => {
    try { return await fn(); } catch (e) {
      if (e instanceof AuthError) expired();
      else toast(e.message);
      return undefined;
    }
  }, [expired]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadOverview = useCallback(() => guard(async () => {
    const zq = zRef.current;
    const ov = await api(zq == null ? "/api/overview" : `/api/overview?z=${zq}`);
    if (ov) {
      setOverview(ov);
      if (zRef.current == null) setZ(ov.z_default);
    }
  }), [guard]);
  const loadApprovals = useCallback(() => guard(async () => setApprovals((await api("/api/approvals")) || [])), [guard]);
  const loadChain = useCallback(() => guard(async () => setChain(await api("/api/audit/verify"))), [guard]);

  useEffect(() => {
    loadOverview(); loadApprovals(); loadChain();
    const t = [setInterval(loadApprovals, 3000), setInterval(loadOverview, 15000), setInterval(loadChain, 15000)];
    return () => t.forEach(clearInterval);
  }, [loadOverview, loadApprovals, loadChain]);

  useEffect(() => { if (z != null) loadOverview(); }, [z]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setMenu(false); }, [hash]);

  const pending = approvals.filter((a) => a.status === "pending");
  const ctx = { me, perms, guard, toast, overview, loadOverview, approvals, loadApprovals, loadChain, z, setZ, chain };

  const nav = [
    ["overview", "Overview"],
    ["run", "Run"],
    ["claims", "Check a claim"],
    ["approvals", "Approvals", pending.length],
    ["performance", "Performance"],
    ["audit", "Audit log"],
  ];

  return (
    <div className="shell">
      <aside className={`side ${menu ? "open" : ""}`} aria-label="Main">
        <a className="brand" href="#intro" title="Play the intro">
          <Mark />
          <span className="brand-name">AegisQ</span>
        </a>
        <nav className="nav">
          {nav.map(([id, label, n]) => (
            <a key={id} href={`#${id}`} aria-current={current === id ? "page" : undefined}>
              {label}
              {n > 0 && <span className="count" aria-label={`${n} waiting`}>{n}</span>}
            </a>
          ))}
          <div className="nav-sep" />
          <a href="#settings" aria-current={current === "settings" ? "page" : undefined}>Settings</a>
        </nav>
        <div className="side-foot">
          <div className="chain" title={chain && !chain.ok ? chain.error : "Every event is hash-chained to the one before"}>
            <span className={`dot ${chain ? (chain.ok ? "safe" : "risk") : "idle"}`} aria-hidden="true" />
            {chain ? (chain.ok ? `Audit log verified, ${chain.entries} events` : "Audit log failed verification") : "Checking audit log"}
          </div>
          <div className="who">
            <span className="avatar" aria-hidden="true">{me.identity.slice(0, 2)}</span>
            <div className="who-text">
              <div className="who-name">{me.identity}</div>
              <div className="who-role">{me.role[0].toUpperCase() + me.role.slice(1)}</div>
            </div>
          </div>
          <button type="button" className="btn small" onClick={signOut}>Sign out</button>
        </div>
      </aside>
      {menu && <div className="scrim" onClick={() => setMenu(false)} aria-hidden="true" />}
      <div>
        <div className="topbar">
          <a className="brand" href="#overview">
            <Mark />
            <span className="brand-name">AegisQ</span>
          </a>
          <button type="button" className="btn small" onClick={() => setMenu(true)} aria-expanded={menu}>Menu</button>
        </div>
        <main className="main">
          <div className="page">
            {current === "overview" && <Overview {...ctx} />}
            {current === "run" && <Run {...ctx} />}
            {current === "claims" && <Claims {...ctx} />}
            {current === "approvals" && <Approvals {...ctx} />}
            {current === "performance" && <Performance {...ctx} />}
            {current === "audit" && <Audit {...ctx} />}
            {current === "settings" && <Settings {...ctx} section={sub} theme={theme} setTheme={setTheme} />}
          </div>
        </main>
      </div>
      {toastNode}
    </div>
  );
}
