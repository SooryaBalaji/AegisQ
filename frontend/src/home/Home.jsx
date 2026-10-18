import FleetMap from "../FleetMap.jsx";
import { Mark } from "../ui.jsx";

const DOCS = "https://github.com/SooryaBalaji/AegisQ#readme";

const ORDER = { plaintext: 0, tls12_only: 1, classical: 2, unreachable: 3, pq_ready: 4 };
const EXAMPLE = Array.from({ length: 56 }, (_, i) => ({
  name: `server-${i + 1}`,
  status: i % 13 === 5 ? "plaintext" : i % 11 === 3 ? "unreachable" : i % 3 === 0 ? "pq_ready" : i % 7 === 1 ? "tls12_only" : "classical",
})).sort((a, b) => ORDER[a.status] - ORDER[b.status]);

const FLOW = [
  ["Scan", "AegisQ offers each TLS and SSH server only a post-quantum key exchange and watches what it does. Nothing on the server changes."],
  ["Rank", "Each server gets a deadline: how long its data must stay secret plus how long a fix takes, compared with your guess for when a quantum computer arrives."],
  ["Fix", "For servers it manages, the agent proposes one line. A person approves it; AegisQ tests, reloads, checks from outside and rolls back on failure."],
  ["Prove", "Every step is written to a hash-chained audit log, and exported as a report and a CycloneDX 1.6 cryptographic bill of materials."],
];

const FIXED = [
  ["nginx", "ssl_ecdh_curve"],
  ["Apache httpd", "SSLOpenSSLConfCmd Groups"],
  ["HAProxy", "ssl-default-bind-curves"],
  ["Caddy", "curves"],
  ["Postfix", "tls_eecdh_auto_curves"],
  ["Dovecot", "ssl_curve_list"],
  ["OpenSSH", "KexAlgorithms"],
];
const ADVISED = [
  "Any TLS or SSH endpoint",
  "SMTP, IMAP and POP3 with STARTTLS",
  "AWS and Google Cloud load balancers",
  "Windows Server (Schannel)",
  "Envoy and lighttpd",
];

const GUARDS = [
  "Only servers you mark as managed can be changed, and only their key-exchange line.",
  "The rules are enforced in code, not in the AI's instructions, so a wrong answer from the model is refused.",
  "Every change needs a named person's approval for that exact change, and not from the person who started the run.",
  "Before anyone is asked, AegisQ checks that the server's own TLS library accepts the change.",
  "Anything applied but not verified when the agent stops is rolled back.",
  "Works without AI too: the rules planner follows the same guardrails.",
];

const SOURCES = [
  ["Fewer than 500,000 physical qubits", "to break 256-bit elliptic-curve keys in minutes.", "Google Quantum AI, March 2026", "https://www.research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/"],
  ["Fewer than 1,000,000 noisy qubits", "to factor RSA-2048 in under a week.", "Gidney, May 2025", "https://arxiv.org/abs/2505.15917"],
];

export default function Home({ signedIn, onReplay }) {
  const app = signedIn ? "#overview" : "#signin";
  return (
    <div className="home">
      <header className="home-head">
        <a className="brand" href="#intro" onClick={(e) => { e.preventDefault(); onReplay(); }} title="Play the intro again">
          <Mark />
          <span className="brand-name">AegisQ</span>
        </a>
        <nav aria-label="Site">
          <a className="btn ghost hide-sm" href={DOCS}>Documentation</a>
          <a className="btn primary" href={app}>{signedIn ? "Open dashboard" : "Sign in"}</a>
        </nav>
      </header>

      <section className="home-hero">
        <div>
          <h1>Move your servers to post-quantum key exchange, safely.</h1>
          <p>
            Traffic recorded today can be decrypted once a large quantum computer exists. AegisQ finds every server that still
            uses classical key exchange, shows which ones matter most, and fixes them one approved, tested, reversible change
            at a time.
          </p>
          <div className="row">
            <a className="btn primary" href={app}>{signedIn ? "Open dashboard" : "Sign in"}</a>
            <a className="btn" href={signedIn ? "#run" : "#signin"}>Scan your servers</a>
          </div>
        </div>
        <figure className="panel home-sample">
          <FleetMap services={EXAMPLE} />
          <figcaption className="panel-body hint">An example fleet: every square is one server, in order of risk.</figcaption>
        </figure>
      </section>

      <section className="home-band">
        <div>
          <h2>How it works</h2>
          <p className="lead">The same four steps run from the dashboard or the aegisq command line.</p>
          <ol className="flow">
            {FLOW.map(([t, d]) => <li key={t}><h3>{t}</h3><p>{d}</p></li>)}
          </ol>
        </div>
      </section>

      <section className="home-band">
        <div className="grid-2">
          <div>
            <h2>Servers it fixes</h2>
            <p className="lead">Changed with approval, tested, verified, and rolled back on failure.</p>
            <table className="data panel">
              <tbody>
                {FIXED.map(([n, k]) => <tr key={n}><td><b>{n}</b></td><td className="muted">{k}</td></tr>)}
              </tbody>
            </table>
          </div>
          <div>
            <h2>Servers it scans and explains</h2>
            <p className="lead">The report names the exact setting their owners should change.</p>
            <table className="data panel">
              <tbody>{ADVISED.map((n) => <tr key={n}><td>{n}</td></tr>)}</tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="home-band">
        <div>
          <h2>The agent can act, but it cannot decide</h2>
          <p className="lead">Gemma 4 or the rules planner chooses the next step. Code decides what is allowed.</p>
          <ul className="guard-list">{GUARDS.map((g) => <li key={g}>{g}</li>)}</ul>
        </div>
      </section>

      <section className="home-band">
        <div>
          <h2>Why now</h2>
          <p className="lead">
            Published estimates of what it takes to break today's key exchange keep falling. Nobody knows the date, so AegisQ
            lets you test different guesses.
          </p>
          <div className="grid-2">
            {SOURCES.map(([fig, claim, src, href]) => (
              <div key={src} className="panel panel-body">
                <p className="stat">{fig}</p>
                <p className="ink2">{claim}</p>
                <a className="hint" href={href}>{src}</a>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="home-foot">
        <span>AegisQ</span>
        <button type="button" className="btn ghost small" onClick={onReplay}>Replay intro</button>
      </footer>
    </div>
  );
}
