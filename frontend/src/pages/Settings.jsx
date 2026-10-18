import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Drawer, Empty, PageHead, Pill, ago, when } from "../ui.jsx";

const ROLES = [
  ["viewer", "Viewer", "Sees results"],
  ["operator", "Operator", "Runs scans and the agent"],
  ["approver", "Approver", "Approves or rejects changes"],
  ["admin", "Admin", "Everything, plus this page"],
];
const INTERVALS = [[60, "Every hour"], [360, "Every 6 hours"], [720, "Every 12 hours"], [1440, "Every day"], [10080, "Every week"]];
const EVENTS = [
  ["exposure", "A server becomes exposed or loses post-quantum protection"],
  ["approval", "A change is waiting for approval"],
  ["job_failed", "A scan or migration fails"],
  ["audit", "The audit log fails verification"],
];

function genPassword() {
  const words = "amber birch cobalt delta ember fjord granite harbor island juniper kestrel lantern meadow nickel orbit pepper quartz river summit timber umber velvet willow yarrow zephyr".split(" ");
  const pick = new Uint32Array(4);
  crypto.getRandomValues(pick);
  return Array.from(pick, (v) => words[v % words.length]).join("-") + `-${pick[0] % 90 + 10}`;
}

function useLoad(path, guard) {
  const [data, setData] = useState(null);
  const load = useCallback(() => guard(async () => setData(await api(path))), [path, guard]);
  useEffect(() => { load(); }, [load]);
  return [data, load];
}

export default function Settings({ section, perms, theme, setTheme, me, guard, toast }) {
  const admin = perms.has("admin");
  const sections = [
    ["appearance", "Appearance"],
    ["account", "Your account"],
    ...(admin ? [["users", "Users"], ["schedules", "Scheduled scans"], ["alerts", "Alerts"]] : []),
  ];
  const current = sections.some(([id]) => id === section) ? section : "appearance";
  return (
    <>
      <PageHead title="Settings" />
      <div className="settings">
        <nav className="subnav" aria-label="Settings sections">
          {sections.map(([id, label]) => (
            <a key={id} href={`#settings/${id}`} aria-current={current === id ? "page" : undefined}>{label}</a>
          ))}
        </nav>
        <div>
          {current === "appearance" && <Appearance theme={theme} setTheme={setTheme} />}
          {current === "account" && <Account me={me} guard={guard} toast={toast} />}
          {current === "users" && admin && <Users me={me} guard={guard} toast={toast} />}
          {current === "schedules" && admin && <Schedules guard={guard} toast={toast} />}
          {current === "alerts" && admin && <Alerts guard={guard} toast={toast} />}
        </div>
      </div>
    </>
  );
}

function Appearance({ theme, setTheme }) {
  return (
    <section className="panel">
      <div className="panel-head"><div><h2>Appearance</h2><p>Saved in this browser.</p></div></div>
      <div className="panel-body">
        <fieldset className="theme-choice">
          <legend className="sr-only">Theme</legend>
          {[["system", "Match my system"], ["light", "Light"], ["dark", "Dark"]].map(([id, label]) => (
            <label key={id}>
              <input type="radio" name="theme" checked={theme === id} onChange={() => setTheme(id)} />
              <span className={`swatch ${id}`} aria-hidden="true"><i /><i /></span>
              <span>{label}</span>
            </label>
          ))}
        </fieldset>
      </div>
    </section>
  );
}

function Account({ me, guard, toast }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const submit = (e) => {
    e.preventDefault();
    setError("");
    if (next !== again) { setError("The new passwords are different."); return; }
    guard(async () => {
      try {
        await api("/api/me/password", { method: "POST", body: { current, password: next } });
        setCurrent(""); setNext(""); setAgain("");
        toast("Password changed. Your other sessions were signed out.");
      } catch (err) { setError(err.message); }
    });
  };
  return (
    <section className="panel">
      <div className="panel-head"><div><h2>Your account</h2><p>Signed in as {me.identity}, {me.role}.</p></div></div>
      <div className="panel-body">
        <form className="form narrow" onSubmit={submit}>
          <input type="text" autoComplete="username" value={me.identity} readOnly hidden />
          <label className="field"><span>Current password</span>
            <input className="input" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
          <label className="field"><span>New password</span>
            <input className="input" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
            <small>At least 12 characters.</small></label>
          <label className="field"><span>Repeat new password</span>
            <input className="input" type="password" autoComplete="new-password" required value={again} onChange={(e) => setAgain(e.target.value)} /></label>
          {error && <p className="error" role="alert">{error}</p>}
          <div><button className="btn primary" type="submit">Change password</button></div>
        </form>
      </div>
    </section>
  );
}

function Users({ me, guard, toast }) {
  const [users, reload] = useLoad("/api/users", guard);
  const [adding, setAdding] = useState(false);
  const [resetting, setResetting] = useState(null);

  const act = (fn, msg) => guard(async () => { await fn(); toast(msg); reload(); });

  return (
    <section className="panel">
      <div className="panel-head">
        <div><h2>Users</h2><p>Who can sign in, and what each person may do.</p></div>
        <button type="button" className="btn primary" onClick={() => setAdding(true)}>Add user</button>
      </div>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Name</th><th>Role</th><th>Added</th><th aria-label="Actions" /></tr></thead>
          <tbody>
            {(users || []).map((u) => (
              <tr key={u.name}>
                <td>
                  <b>{u.name}</b>{u.name === me.identity && <span className="muted"> (you)</span>}
                  {!u.has_password && <div><Pill tone="warn">No password yet</Pill></div>}
                </td>
                <td>
                  <select className="select compact" aria-label={`Role for ${u.name}`} value={u.role}
                    onChange={(e) => act(() => api(`/api/users/${encodeURIComponent(u.name)}`, { method: "PATCH", body: { role: e.target.value } }), `${u.name} is now ${e.target.value}`)}>
                    {ROLES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                  </select>
                </td>
                <td className="nowrap">{u.created_at ? ago(u.created_at) : ""}<div className="sub">{u.created_by ? `by ${u.created_by.replace(/^cli:/, "")}` : ""}</div></td>
                <td className="num nowrap">
                  <button type="button" className="btn small" onClick={() => setResetting(u.name)}>Set password</button>{" "}
                  <button type="button" className="btn small danger" disabled={u.name === me.identity}
                    onClick={() => window.confirm(`Remove ${u.name}? They are signed out at once.`) &&
                      act(() => api(`/api/users/${encodeURIComponent(u.name)}`, { method: "DELETE" }), `${u.name} removed`)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="panel-body hint">
        Roles: {ROLES.map(([, label, d]) => `${label.toLowerCase()} ${d.toLowerCase()}`).join("; ")}.
      </div>
      {adding && <UserForm title="Add user" onClose={() => setAdding(false)} guard={guard}
        onSave={async (b) => { await api("/api/users", { method: "POST", body: b }); toast(`${b.name} can now sign in`); reload(); }} />}
      {resetting && <UserForm title={`New password for ${resetting}`} name={resetting} onClose={() => setResetting(null)} guard={guard}
        onSave={async (b) => { await api(`/api/users/${encodeURIComponent(resetting)}/password`, { method: "POST", body: { password: b.password } }); toast(`New password set for ${resetting}. They were signed out.`); reload(); }} />}
    </section>
  );
}

function UserForm({ title, name: fixed, onSave, onClose, guard }) {
  const [name, setName] = useState(fixed || "");
  const [role, setRole] = useState("operator");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const submit = (e) => {
    e.preventDefault();
    setError("");
    guard(async () => {
      try { await onSave({ name: name.trim(), role, password }); onClose(); } catch (err) { setError(err.message); }
    });
  };
  return (
    <Drawer title={title} onClose={onClose}>
      <form className="form drawer-form" onSubmit={submit}>
        {!fixed && (
          <>
            <label className="field"><span>User name</span>
              <input className="input" required autoFocus pattern="[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}" value={name} onChange={(e) => setName(e.target.value)} />
              <small>Letters, digits, dots, dashes, underscores or @.</small></label>
            <fieldset className="choice">
              <legend className="field"><span>Role</span></legend>
              {ROLES.map(([id, label, d]) => (
                <label key={id} className="choice-item">
                  <input type="radio" name="role" checked={role === id} onChange={() => setRole(id)} />
                  <span><b>{label}</b><small>{d}</small></span>
                </label>
              ))}
            </fieldset>
          </>
        )}
        <label className="field"><span>Password</span>
          <div className="row nowrap-row">
            <input className="input grow" type="text" autoComplete="off" spellCheck={false} required minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="button" className="btn" onClick={() => setPassword(genPassword())}>Generate</button>
          </div>
          <small>At least 12 characters. Give it to them in person or through your password manager; they can change it in Settings.</small></label>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="row">
          <button className="btn primary" type="submit">{fixed ? "Set password" : "Add user"}</button>
          <button className="btn" type="button" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Drawer>
  );
}

function Schedules({ guard, toast }) {
  const [list, reload] = useLoad("/api/schedules", guard);
  const [caps] = useLoad("/api/capabilities", guard);
  const [minutes, setMinutes] = useState(1440);
  const ok = caps?.schedules;
  const act = (fn, msg) => guard(async () => { await fn(); toast(msg); reload(); });
  const label = (m) => (INTERVALS.find(([v]) => v === m) || [0, `Every ${m >= 60 ? `${m / 60} hours` : `${m} minutes`}`])[1];
  return (
    <section className="panel">
      <div className="panel-head"><div><h2>Scheduled scans</h2><p>Rescan the inventory on a timer. Scans change nothing; fixes still wait for a person.</p></div></div>
      {list?.length ? (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>How often</th><th>Next scan</th><th>Last scan</th><th>State</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.id}>
                  <td>{label(s.every_minutes)}</td>
                  <td>{s.enabled ? when(s.next_run) : <span className="muted">Paused</span>}</td>
                  <td>{s.last_run ? ago(s.last_run) : <span className="muted">Not yet</span>}</td>
                  <td><Pill tone={s.enabled ? "safe" : "idle"}>{s.enabled ? "On" : "Paused"}</Pill></td>
                  <td className="num nowrap">
                    <button type="button" className="btn small" onClick={() => act(() => api(`/api/schedules/${s.id}`, { method: "PATCH", body: { enabled: !s.enabled } }), s.enabled ? "Paused" : "Resumed")}>{s.enabled ? "Pause" : "Resume"}</button>{" "}
                    <button type="button" className="btn small danger" onClick={() => act(() => api(`/api/schedules/${s.id}`, { method: "DELETE" }), "Schedule deleted")}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <Empty title="No scheduled scans" />}
      <div className="panel-body border-top">
        <form className="row" onSubmit={(e) => { e.preventDefault(); act(() => api("/api/schedules", { method: "POST", body: { every_minutes: Number(minutes) } }), "Schedule added"); }}>
          <select className="select auto" aria-label="How often" value={minutes} disabled={!ok} onChange={(e) => setMinutes(Number(e.target.value))}>
            {INTERVALS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          <button type="submit" className="btn primary" disabled={!ok}>Add schedule</button>
          <span className="hint">{ok ? "Runs while the dashboard is running." : "Needs `aegisq serve --inventory FILE` without --read-only."}</span>
        </form>
      </div>
    </section>
  );
}

function Alerts({ guard, toast }) {
  const [data, reload] = useLoad("/api/alerts", guard);
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState(() => new Set(EVENTS.map(([e]) => e)));
  const toggle = (e) => setEvents((s) => { const n = new Set(s); if (n.has(e)) n.delete(e); else n.add(e); return n; });
  const add = (e) => {
    e.preventDefault();
    guard(async () => {
      await api("/api/alerts", { method: "POST", body: { url: url.trim(), events: [...events] } });
      setUrl(""); toast("Webhook added"); reload();
    });
  };
  const test = () => guard(async () => {
    const res = await api("/api/alerts/test", { method: "POST" });
    toast(res.length ? res.map((r) => (r.ok ? "Delivered" : `Failed: ${r.status}`)).join(", ") : "Add a webhook first.");
    reload();
  });
  return (
    <section className="panel">
      <div className="panel-head">
        <div><h2>Alerts</h2><p>Messages to Slack, Teams or any HTTPS webhook.</p></div>
        <button type="button" className="btn" onClick={test} disabled={!data?.alerts?.length}>Send a test alert</button>
      </div>
      {data?.alerts?.length ? (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Webhook</th><th>Sends</th><th>Last delivery</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.id}>
                  <td className="wrap">{a.url}</td>
                  <td className="wrap ink2">{a.events.map((e) => EVENTS.find(([k]) => k === e)?.[1] || e).join("; ")}</td>
                  <td className="nowrap">{a.last_status ? <>{a.last_status}<div className="sub">{ago(a.last_sent_at)}</div></> : <span className="muted">Never</span>}</td>
                  <td className="num"><button type="button" className="btn small danger" onClick={() => guard(async () => { await api(`/api/alerts/${a.id}`, { method: "DELETE" }); toast("Webhook deleted"); reload(); })}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <Empty title="No webhooks yet" />}
      <div className="panel-body border-top">
        <form className="form narrow" onSubmit={add}>
          <label className="field"><span>Webhook address</span>
            <input className="input" type="url" required spellCheck={false} placeholder="https://hooks.slack.com/services/..." value={url} onChange={(e) => setUrl(e.target.value)} />
            <small>Stored on the server and shown shortened. AegisQ posts JSON with a text field, which Slack and Teams show as a message.</small></label>
          <fieldset className="checks">
            <legend className="field"><span>Send when</span></legend>
            {EVENTS.map(([e, label]) => (
              <label key={e} className="check"><input type="checkbox" checked={events.has(e)} onChange={() => toggle(e)} /> {label}</label>
            ))}
          </fieldset>
          <div><button className="btn primary" type="submit" disabled={!events.size}>Add webhook</button></div>
        </form>
      </div>
    </section>
  );
}
