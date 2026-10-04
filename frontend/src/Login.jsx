import { useState } from "react";

export default function Login({ onSubmit, error }) {
  const [value, setValue] = useState("");
  return (
    <section className="login" aria-labelledby="login-title">
      <span className="eyebrow">Post-quantum readiness</span>
      <h1 id="login-title" className="display">Sign in to AegisQ.</h1>
      <p className="lede">Paste your API token: one from <code>AEGISQ_API_TOKENS</code>, or the one printed by <code>aegisq serve</code>.</p>
      <form className="login-form" onSubmit={(e) => { e.preventDefault(); onSubmit(value.trim()); }}>
        <input type="password" autoComplete="off" placeholder="API token" required minLength={8} aria-label="API token"
          value={value} onChange={(e) => setValue(e.target.value)} />
        <button type="submit" className="pill">Sign in</button>
      </form>
      <p className="login-error">{error}</p>
    </section>
  );
}
