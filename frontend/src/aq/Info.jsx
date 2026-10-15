import { motion } from "framer-motion";

const OUT = [0.16, 1, 0.3, 1];

const STEPS = [
  ["01", "Scan", "A real handshake against every TLS and SSH service: will it complete a post-quantum key exchange if that is the only option offered? Scanning changes nothing."],
  ["02", "Rank", "Mosca's inequality, X + Y > Z: how long the data must stay secret, plus the time to migrate, against when a quantum computer could break it. Exposed services rise to the top."],
  ["03", "Fix", "An agent proposes the smallest config change. A named person approves it. AegisQ applies it, re-tests the handshake, and rolls back on its own if anything fails."],
  ["04", "Prove", "Every step lands in a hash-chained audit log, exported as a migration report and a CycloneDX 1.6 cryptographic bill of materials."],
];

const GUARDS = [
  "Only services you mark as managed can be touched.",
  "Only key-exchange lines can change, enforced in code rather than in a prompt.",
  "Every change needs a named person's approval, bound to the exact diff.",
  "A config test runs before every reload, plus a TLS library check where that test would miss a problem.",
  "Anything left unverified when the agent stops is rolled back.",
  "Works with no AI at all: the rules planner uses the same guardrails.",
];

const SOURCES = [
  {
    figure: "< 500,000",
    unit: "physical qubits",
    claim: "to break 256-bit elliptic-curve keys, in minutes",
    source: "Google Quantum AI, March 2026",
    href: "https://www.research.google/blog/safeguarding-cryptocurrency-by-disclosing-quantum-vulnerabilities-responsibly/",
  },
  {
    figure: "< 1,000,000",
    unit: "noisy qubits",
    claim: "to factor RSA-2048, in under a week",
    source: "Gidney, May 2025",
    href: "https://arxiv.org/abs/2505.15917",
  },
];

function Reveal({ children, delay = 0, className = "" }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }}
      transition={{ duration: 0.9, delay, ease: OUT }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

function Mark() {
  return (
    <motion.svg
      viewBox="-60 -60 120 120"
      className="h-[min(56vw,300px)] w-[min(56vw,300px)] overflow-visible"
      aria-hidden="true"
      initial={{ scale: 1.5, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 1.4, ease: OUT }}
    >
      <motion.circle r={44} fill="none" stroke="#A1A1AA" strokeWidth={0.4} strokeDasharray="1 3"
        animate={{ rotate: 360 }} transition={{ duration: 60, repeat: Infinity, ease: "linear" }} />
      <circle r={30} fill="none" stroke="#A1A1AA" strokeWidth={0.4} opacity={0.6} />
      <circle r={16} fill="none" stroke="#FFFFFF" strokeWidth={0.6} />
      <motion.circle r={4} fill="#FFFFFF" animate={{ r: [4, 4.6, 4] }} transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }} />
      <motion.circle r={16} fill="none" stroke="#FFFFFF" strokeWidth={0.5}
        animate={{ r: [16, 52], opacity: [0.5, 0] }} transition={{ duration: 3.2, repeat: Infinity, ease: "easeOut" }} />
    </motion.svg>
  );
}

const MANAGED = [
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
  "AWS load balancers",
  "Google Cloud load balancers",
  "Windows Server (Schannel)",
  "Envoy",
  "lighttpd",
];

function Label({ children }) {
  return <div className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-zinc-500">{children}</div>;
}

function Ctas({ signedIn }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <a href="#run" className="rounded-full bg-paper px-6 py-2.5 text-sm font-medium text-ink no-underline transition-opacity hover:opacity-85">
        Run a scan →
      </a>
      <a href={signedIn ? "#overview" : "#signin"} className="rounded-full border border-white/25 px-6 py-2.5 text-sm text-paper no-underline transition-colors hover:border-paper">
        Open dashboard
      </a>
    </div>
  );
}

export default function Info({ signedIn, onReplay }) {
  return (
    <div className="mx-auto w-full max-w-6xl px-6 sm:px-10">
      <section className="grid min-h-[100svh] items-center gap-12 pb-16 pt-32 lg:grid-cols-[1.25fr_1fr]">
        <div className="min-w-0">
          <Reveal><Label>Post-quantum migration engine</Label></Reveal>
          <Reveal delay={0.1}>
            <h1 className="mt-6 text-[2.4rem] font-light leading-[1.05] tracking-[-0.03em] text-paper sm:text-6xl">
              Move your servers to post-quantum key exchange, safely.
            </h1>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="mt-7 max-w-xl text-[16px] leading-relaxed text-zinc-400 sm:text-[17px]">
              Traffic recorded today can be decrypted once a large quantum computer exists. AegisQ finds every TLS and SSH
              service that is still classical, ranks the ones that matter most, and migrates them one approved, verified,
              reversible change at a time.
            </p>
          </Reveal>
          <Reveal delay={0.3} className="mt-10"><Ctas signedIn={signedIn} /></Reveal>
        </div>
        <div className="flex justify-center lg:justify-end"><Mark /></div>
      </section>

      <section className="border-t border-white/10 py-24">
        <Reveal><Label>How it works</Label></Reveal>
        <div className="mt-12 grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map(([n, title, body], i) => (
            <Reveal key={n} delay={i * 0.08} className="bg-ink p-7">
              <div className="font-mono text-[11px] text-zinc-500">{n}</div>
              <h2 className="mt-4 text-xl font-light text-paper">{title}</h2>
              <p className="mt-3 text-[14px] leading-relaxed text-zinc-400">{body}</p>
            </Reveal>
          ))}
        </div>
      </section>

      <section className="grid gap-12 border-t border-white/10 py-24 lg:grid-cols-[1fr_1.4fr]">
        <Reveal>
          <Label>The change</Label>
          <h2 className="mt-5 text-3xl font-light leading-tight tracking-tight text-paper">One line per server.</h2>
          <p className="mt-4 max-w-md text-[15px] leading-relaxed text-zinc-400">
            A hybrid key exchange keeps the classical algorithm alongside the post-quantum one, so older clients still connect
            and the session stays secure if either holds.
          </p>
        </Reveal>
        <div className="flex min-w-0 flex-col gap-4">
          <Reveal className="min-w-0 rounded-2xl border border-white/10 p-6">
            <div className="flex items-baseline justify-between gap-4">
              <span className="text-sm text-paper">nginx</span>
              <span className="font-mono text-[10.5px] text-zinc-500">OpenSSL 3.5+</span>
            </div>
            <pre className="mt-4 whitespace-pre-wrap break-all font-mono text-[12.5px] text-zinc-300">ssl_ecdh_curve X25519MLKEM768:X25519;</pre>
          </Reveal>
          <Reveal delay={0.1} className="min-w-0 rounded-2xl border border-white/10 p-6">
            <div className="flex items-baseline justify-between gap-4">
              <span className="text-sm text-paper">OpenSSH</span>
              <span className="text-right font-mono text-[10.5px] text-zinc-500">mlkem768 on 9.9+ · sntrup761 on 8.5+</span>
            </div>
            <pre className="mt-4 whitespace-pre-wrap break-all font-mono text-[12.5px] text-zinc-300">KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256</pre>
          </Reveal>
        </div>
      </section>

      <section className="border-t border-white/10 py-24">
        <Reveal><Label>Servers</Label></Reveal>
        <Reveal delay={0.05}>
          <h2 className="mt-5 max-w-2xl text-3xl font-light leading-tight tracking-tight text-paper">
            Scans everything. Fixes the servers it can test.
          </h2>
        </Reveal>
        <div className="mt-12 grid gap-12 lg:grid-cols-2">
          <Reveal className="min-w-0">
            <p className="text-[14px] text-zinc-500">Changed with approval, tested, verified, rolled back on failure</p>
            <ul className="m-0 mt-4 list-none p-0">
              {MANAGED.map(([name, key]) => (
                <li key={name} className="flex items-baseline justify-between gap-4 border-t border-white/10 py-3.5">
                  <span className="text-[15px] text-paper">{name}</span>
                  <span className="truncate text-right font-mono text-[12px] text-zinc-500">{key}</span>
                </li>
              ))}
            </ul>
          </Reveal>
          <Reveal delay={0.1} className="min-w-0">
            <p className="text-[14px] text-zinc-500">Scanned, with the exact setting to change</p>
            <ul className="m-0 mt-4 list-none p-0">
              {ADVISED.map((name) => (
                <li key={name} className="border-t border-white/10 py-3.5 text-[15px] text-zinc-300">{name}</li>
              ))}
            </ul>
          </Reveal>
        </div>
      </section>

      <section className="border-t border-white/10 py-24">
        <Reveal><Label>Guardrails</Label></Reveal>
        <Reveal delay={0.05}>
          <h2 className="mt-5 max-w-2xl text-3xl font-light leading-tight tracking-tight text-paper">
            The agent has autonomy, not authority.
          </h2>
        </Reveal>
        <div className="mt-12 grid gap-x-10 sm:grid-cols-2 lg:grid-cols-3">
          {GUARDS.map((g, i) => (
            <Reveal key={g} delay={(i % 3) * 0.06} className="flex gap-4 border-t border-white/10 py-6">
              <span className="mt-2 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-paper" />
              <p className="text-[15px] leading-relaxed text-zinc-300">{g}</p>
            </Reveal>
          ))}
        </div>
      </section>

      <section className="border-t border-white/10 py-24">
        <Reveal><Label>Why now</Label></Reveal>
        <div className="mt-12 grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10 md:grid-cols-2">
          {SOURCES.map((s, i) => (
            <Reveal key={s.source} delay={i * 0.1} className="bg-ink p-8">
              <div className="flex items-baseline gap-3">
                <span className="text-4xl font-light tracking-tight text-paper sm:text-5xl">{s.figure}</span>
                <span className="font-mono text-[11px] text-zinc-500">{s.unit}</span>
              </div>
              <p className="mt-3 text-[15px] text-zinc-300">{s.claim}</p>
              <a href={s.href} className="mt-5 inline-block font-mono text-[11px] text-zinc-500 underline decoration-white/20 underline-offset-4 transition-colors hover:text-paper">
                {s.source} ↗
              </a>
            </Reveal>
          ))}
        </div>
        <Reveal delay={0.15}>
          <p className="mt-6 max-w-2xl text-[13.5px] leading-relaxed text-zinc-500">
            Published resource estimates, not dates. Nobody knows when such a machine will exist, which is why AegisQ lets you
            test different guesses for Z and shows which services are exposed under each.
          </p>
        </Reveal>
      </section>

      <section className="border-t border-white/10 py-24">
        <Reveal><Label>Built on</Label></Reveal>
        <Reveal delay={0.05}>
          <div className="mt-8 flex flex-wrap gap-x-8 gap-y-3 font-mono text-[12.5px] text-zinc-400">
            <span>FIPS 203 ML-KEM</span><span>X25519MLKEM768</span><span>mlkem768x25519-sha256</span>
            <span>sntrup761x25519</span><span>CycloneDX 1.6 CBOM</span><span>Mosca X + Y &gt; Z</span>
          </div>
        </Reveal>
      </section>

      <section className="flex flex-col items-start gap-8 border-t border-white/10 py-24 sm:flex-row sm:items-center sm:justify-between">
        <Reveal>
          <h2 className="max-w-xl text-3xl font-light leading-tight tracking-tight text-paper">See where your fleet stands.</h2>
        </Reveal>
        <Reveal delay={0.1}><Ctas signedIn={signedIn} /></Reveal>
      </section>

      <footer className="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 py-8 font-mono text-[11px] text-zinc-500">
        <span className="tracking-[0.42em] text-paper">AEGISQ</span>
        <button type="button" onClick={onReplay} className="text-zinc-400 transition-colors hover:text-paper">
          ↺ Replay intro
        </button>
      </footer>
    </div>
  );
}
