import { useCallback, useEffect, useState } from "react";

const ROLES = [
  ["viewer", "sees results"],
  ["operator", "runs scans and the agent"],
  ["approver", "approves or rejects changes"],
  ["admin", "everything, plus this page"],
];
const INTERVALS = [[60, "Every hour"], [360, "Every 6 hours"], [720, "Every 12 hours"], [1440, "Every day"], [10080, "Every week"]];
const EVENTS = [
  ["exposure", "A service becomes exposed or loses post-quantum protection"],
  ["approval", "A change is waiting for approval"],
  ["job_failed", "A scan or migration fails"],
  ["audit", "The audit log fails verification"],
];

const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
const every = (m) => (INTERVALS.find(([v]) => v === m) || [0, `Every ${m >= 60 ? `${m / 60} h` : `${m} min`}`])[1];

function useLoad(client, path) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setData(await client.api(path)); setError(""); } catch (e) { setError(e.message); }
  }, [client, path]);
  useEffect(() => { load(); }, [load]);
  return [data, load, error];
}

function Token({ value, onClose }) {
  if (!value) return null;
  return (
    <div className="pending-item">
      <div className="row-between"><strong>{`Token for ${value.name}`}</strong><button type="button" className="ghost small-btn" onClick={onClose}>Done</button></div>
      <p className="muted small">Shown only once. Send it to them privately; they paste it to sign in. Issue a new one if it is lost.</p>
      <pre className="log" tabIndex={0}>{value.token}</pre>
    </div>
  );
}

function Users({ client, me }) {
  const [users, reload, error] = useLoad(client, "/api/users");
  const [name, setName] = useState("");
  const [role, setRole] = useState("operator");
  const [token, setToken] = useState(null);
  const [msg, setMsg] = useState("");

  const act = async (fn) => {
    setMsg("");
    try { await fn(); } catch (e) { setMsg(e.message); }
    reload();
  };
  const add = (e) => {
    e.preventDefault();
    act(async () => {
      const r = await client.api("/api/users", { method: "POST", body: JSON.stringify({ name: name.trim(), role }) });
      setToken(r); setName("");
    });
  };

  return (
    <section className="card" aria-labelledby="users-title">
      <h2 id="users-title">Users <span className="muted">who can sign in, and what they may do</span></h2>
      <div className="grid2">
        <div className="scroll">
          <table className="data">
            <thead><tr><th>Name</th><th>Role</th><th>Source</th><th aria-label="Actions"></th></tr></thead>
            <tbody>{(users || []).map((u) => (
              <tr key={u.name}>
                <td>{u.name}{u.name === me.identity && <span className="muted small"> (you)</span>}</td>
                <td>
                  {u.source === "database" ? (
                    <select className="role-select" value={u.role} aria-label={`Role for ${u.name}`}
                      onChange={(e) => act(() => client.api(`/api/users/${encodeURIComponent(u.name)}`, { method: "PATCH", body: JSON.stringify({ role: e.target.value }) }))}>
                      {ROLES.map(([r]) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  ) : u.role}
                </td>
                <td className="small muted">{u.source === "database" ? `added by ${u.created_by || "–"}` : "AEGISQ_API_TOKENS"}</td>
                <td className="num">
                  {u.source === "database" && (
                    <span className="actions">
                      <button type="button" className="ghost small-btn" onClick={() => act(async () => setToken(await client.api(`/api/users/${encodeURIComponent(u.name)}/token`, { method: "POST" })))}>New token</button>
                      <button type="button" className="danger small-btn" onClick={() => confirm(`Remove ${u.name}? Their token stops working.`) && act(() => client.api(`/api/users/${encodeURIComponent(u.name)}`, { method: "DELETE" }))}>Remove</button>
                    </span>
                  )}
                </td>
              </tr>
            ))}</tbody>
          </table>
          {(error || msg) && <p className="bad small">{error || msg}</p>}
        </div>
        <div>
          <form className="run-card" onSubmit={add}>
            <h3>Add a user</h3>
            <label htmlFor="u-name">Name</label>
            <input id="u-name" type="text" required pattern="[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}" placeholder="alex" value={name} onChange={(e) => setName(e.target.value)} />
            <label htmlFor="u-role">Role</label>
            <select id="u-role" value={role} onChange={(e) => setRole(e.target.value)}>
              {ROLES.map(([r, d]) => <option key={r} value={r}>{`${r} — ${d}`}</option>)}
            </select>
            <div className="btns"><button type="submit">Create and show token</button></div>
            <p className="muted small">Tokens are stored only as hashes. Users from AEGISQ_API_TOKENS are managed in that variable.</p>
          </form>
          <Token value={token} onClose={() => setToken(null)} />
        </div>
      </div>
    </section>
  );
}

function Schedules({ client, caps }) {
  const [list, reload, error] = useLoad(client, "/api/schedules");
  const [minutes, setMinutes] = useState(1440);
  const [msg, setMsg] = useState("");
  const act = async (fn) => { setMsg(""); try { await fn(); } catch (e) { setMsg(e.message); } reload(); };
  const ok = caps && caps.schedules;

  return (
    <section className="card" aria-labelledby="sch-title">
      <h2 id="sch-title">Scheduled scans <span className="muted">rescan the inventory automatically</span></h2>
      <div className="grid2">
        <div className="scroll">
          {list && list.length ? (
            <table className="data">
              <thead><tr><th>Interval</th><th>Next run</th><th>Last run</th><th>State</th><th aria-label="Actions"></th></tr></thead>
              <tbody>{list.map((s) => (
                <tr key={s.id}>
                  <td>{every(s.every_minutes)}</td>
                  <td className="small">{s.enabled ? when(s.next_run) : "–"}</td>
                  <td className="small">{when(s.last_run)}</td>
                  <td><span className={`badge s-${s.enabled ? "good" : "muted"}`}>{s.enabled ? "on" : "paused"}</span></td>
                  <td className="num">
                    <span className="actions">
                      <button type="button" className="ghost small-btn" onClick={() => act(() => client.api(`/api/schedules/${s.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !s.enabled }) }))}>{s.enabled ? "Pause" : "Resume"}</button>
                      <button type="button" className="danger small-btn" onClick={() => act(() => client.api(`/api/schedules/${s.id}`, { method: "DELETE" }))}>Delete</button>
                    </span>
                  </td>
                </tr>
              ))}</tbody>
            </table>
          ) : <p className="muted">No scheduled scans.</p>}
          {(error || msg) && <p className="bad small">{error || msg}</p>}
        </div>
        <form className="run-card" onSubmit={(e) => { e.preventDefault(); act(() => client.api("/api/schedules", { method: "POST", body: JSON.stringify({ every_minutes: Number(minutes) }) })); }}>
          <h3>Add a schedule</h3>
          <label htmlFor="s-every">How often</label>
          <select id="s-every" value={minutes} disabled={!ok} onChange={(e) => setMinutes(Number(e.target.value))}>
            {INTERVALS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          <div className="btns"><button type="submit" disabled={!ok}>Add schedule</button></div>
          <p className="muted small">{ok
            ? "Runs while `aegisq serve` is running. Scans change nothing; fixes always wait for a person."
            : "Needs `aegisq serve --inventory FILE` (and not --read-only)."}</p>
        </form>
      </div>
    </section>
  );
}

function Alerts({ client }) {
  const [data, reload, error] = useLoad(client, "/api/alerts");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState(() => new Set(EVENTS.map(([e]) => e)));
  const [msg, setMsg] = useState("");
  const act = async (fn) => { setMsg(""); try { await fn(); } catch (e) { setMsg(e.message); } reload(); };
  const toggle = (e) => setEvents((s) => { const n = new Set(s); if (n.has(e)) n.delete(e); else n.add(e); return n; });

  const test = () => act(async () => {
    const res = await client.api("/api/alerts/test", { method: "POST" });
    setMsg(res.length ? res.map((r) => `${r.ok ? "delivered" : "failed"}: ${r.status}`).join(" · ") : "No webhooks configured.");
  });

  return (
    <section className="card" aria-labelledby="al-title">
      <h2 id="al-title">Alerts <span className="muted">Slack, Teams or any HTTPS webhook</span></h2>
      <div className="grid2">
        <div className="scroll">
          {data && data.alerts.length ? (
            <table className="data">
              <thead><tr><th>Webhook</th><th>Events</th><th>Last delivery</th><th aria-label="Actions"></th></tr></thead>
              <tbody>{data.alerts.map((a) => (
                <tr key={a.id}>
                  <td className="mono small">{a.url}</td>
                  <td className="small">{a.events.join(", ")}</td>
                  <td className="small">{a.last_status ? `${a.last_status} · ${when(a.last_sent_at)}` : "–"}</td>
                  <td className="num"><button type="button" className="danger small-btn" onClick={() => act(() => client.api(`/api/alerts/${a.id}`, { method: "DELETE" }))}>Delete</button></td>
                </tr>
              ))}</tbody>
            </table>
          ) : <p className="muted">No webhooks yet.</p>}
          <div className="btns"><button type="button" className="ghost" onClick={test}>Send a test alert</button></div>
          {(error || msg) && <p className={`small ${msg.startsWith("delivered") ? "" : "bad"}`}>{error || msg}</p>}
        </div>
        <form className="run-card" onSubmit={(e) => {
          e.preventDefault();
          act(async () => { await client.api("/api/alerts", { method: "POST", body: JSON.stringify({ url: url.trim(), events: [...events] }) }); setUrl(""); });
        }}>
          <h3>Add a webhook</h3>
          <label htmlFor="a-url">Webhook URL</label>
          <input id="a-url" type="url" required placeholder="https://hooks.slack.com/services/…" spellCheck={false} value={url} onChange={(e) => setUrl(e.target.value)} />
          <fieldset>
            <legend>Send when</legend>
            <div className="checks">
              {EVENTS.map(([e, label]) => (
                <label className="check" key={e}><input type="checkbox" checked={events.has(e)} onChange={() => toggle(e)} />{` ${label}`}</label>
              ))}
            </div>
          </fieldset>
          <div className="btns"><button type="submit" disabled={!events.size}>Add webhook</button></div>
          <p className="muted small">AegisQ posts JSON with a <code>text</code> field, which Slack and Teams incoming webhooks display as a message. The URL is stored on the server and shown masked.</p>
        </form>
      </div>
    </section>
  );
}

export default function Settings({ client, me }) {
  const [caps] = useLoad(client, "/api/capabilities");
  return (
    <>
      <Users client={client} me={me} />
      <Schedules client={client} caps={caps} />
      <Alerts client={client} />
    </>
  );
}
