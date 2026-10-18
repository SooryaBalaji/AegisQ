import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Mark } from "../ui.jsx";

export default function SignIn({ onSignedIn }) {
  const [setup, setSetup] = useState(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api("/api/setup").then(setSetup).catch(() => setSetup({ needed: false, allowed: false }));
  }, []);

  if (!setup) return null;
  const first = setup.needed;

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (first && password !== confirm) { setError("The two passwords are different."); return; }
    setBusy(true);
    try {
      onSignedIn(await api(first ? "/api/setup" : "/api/login", { method: "POST", body: { name: name.trim(), password } }));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="auth-card">
        <a className="brand" href="#intro">
          <Mark />
          <span className="brand-name">AegisQ</span>
        </a>
        <section className="panel">
          <div className="panel-body">
            {first && !setup.allowed ? (
              <>
                <h1>Create the first admin</h1>
                <p className="lead">
                  For safety, the first account can only be created on the computer running AegisQ. Open this page
                  there, or run <b>aegisq users add NAME --role admin</b>.
                </p>
              </>
            ) : (
              <form className="form" onSubmit={submit}>
                <div>
                  <h1>{first ? "Create the first admin" : "Sign in"}</h1>
                  <p className="lead">
                    {first
                      ? "This account can add other people and choose what each of them can do."
                      : "Use the name and password your AegisQ admin gave you."}
                  </p>
                </div>
                <label className="field">
                  <span>User name</span>
                  <input className="input" autoComplete="username" autoFocus required value={name} onChange={(e) => setName(e.target.value)} />
                </label>
                <label className="field">
                  <span>Password</span>
                  <input
                    className="input"
                    type="password"
                    autoComplete={first ? "new-password" : "current-password"}
                    required
                    minLength={first ? 12 : undefined}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  {first && <small>At least 12 characters.</small>}
                </label>
                {first && (
                  <label className="field">
                    <span>Repeat password</span>
                    <input className="input" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                  </label>
                )}
                {error && <p className="error" role="alert">{error}</p>}
                <button className="btn primary" type="submit" disabled={busy}>
                  {first ? "Create admin and sign in" : busy ? "Signing in" : "Sign in"}
                </button>
              </form>
            )}
          </div>
        </section>
        {!first && <p className="auth-foot">Forgot your password? An admin can set a new one in Settings.</p>}
      </div>
    </div>
  );
}
