import { useEffect, useRef, useState } from "react";

export const STATUS = {
  pq_ready: { label: "Post-quantum", tone: "safe" },
  classical: { label: "Classical", tone: "warn" },
  tls12_only: { label: "TLS 1.2 only", tone: "warn" },
  legacy_tls: { label: "Legacy TLS", tone: "risk" },
  plaintext: { label: "Plaintext", tone: "risk" },
  unreachable: { label: "Unreachable", tone: "idle" },
  error: { label: "Error", tone: "idle" },
};

export const SEVERITY = {
  critical: { label: "Critical", tone: "risk" },
  high: { label: "High", tone: "risk" },
  medium: { label: "Medium", tone: "warn" },
  low: { label: "Low", tone: "warn" },
  none: { label: "Protected", tone: "safe" },
  unknown: { label: "Unknown", tone: "idle" },
};

const GROUP_NAMES = { x25519: "X25519", x448: "X448", secp256r1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };
export const groupName = (g) => (g ? GROUP_NAMES[g] || g : g);

export const tone = (status) => (STATUS[status] || { tone: "idle" }).tone;

export function Status({ status }) {
  const s = STATUS[status] || { label: status || "Not scanned", tone: "idle" };
  return (
    <span className="status">
      <span className={`dot ${s.tone}`} aria-hidden="true" />
      {s.label}
    </span>
  );
}

export function Pill({ tone: t = "idle", children, title }) {
  return <span className={`pill ${t}`} title={title}>{children}</span>;
}

export function Mark({ className = "brand-mark" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <rect x="1.5" y="1.5" width="21" height="21" rx="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <rect x="6" y="6" width="5" height="5" rx="1.2" fill="currentColor" />
      <rect x="13" y="6" width="5" height="5" rx="1.2" fill="currentColor" opacity="0.35" />
      <rect x="6" y="13" width="5" height="5" rx="1.2" fill="currentColor" opacity="0.35" />
      <rect x="13" y="13" width="5" height="5" rx="1.2" fill="currentColor" />
    </svg>
  );
}

export function PageHead({ title, children, actions }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {children && <p>{children}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Panel({ title, sub, actions, children, flush = false, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <div className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <p>{sub}</p>}
          </div>
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      {flush ? children : <div className="panel-body">{children}</div>}
    </section>
  );
}

export function Empty({ title, children }) {
  return (
    <div className="empty">
      <b>{title}</b>
      {children}
    </div>
  );
}

export function Diff({ text }) {
  return (
    <div className="diff" role="region" aria-label="Proposed change" tabIndex={0}>
      {text.split("\n").filter((l, i, a) => l || i < a.length - 1).map((line, i) => {
        if (line.startsWith("+++") || line.startsWith("---")) return <div key={i} className="ctx">{line}</div>;
        const cls = line.startsWith("@@") ? "hunk" : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "ctx";
        return <div key={i} className={cls}>{line || " "}</div>;
      })}
    </div>
  );
}

export function Drawer({ title, sub, onClose, children }) {
  const ref = useRef(null);
  useEffect(() => {
    const prev = document.activeElement;
    ref.current?.focus();
    const key = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", key);
    return () => { window.removeEventListener("keydown", key); prev?.focus?.(); };
  }, [onClose]);
  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <div className="drawer-head">
          <div>
            <h2>{title}</h2>
            {sub && <div className="muted">{sub}</div>}
          </div>
          <button type="button" className="btn ghost icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 3.5l9 9m0-9l-9 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function useToast() {
  const [msg, setMsg] = useState("");
  const timer = useRef(null);
  const show = (m) => {
    setMsg(m);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setMsg(""), 3200);
  };
  const node = msg ? <div className="toast" role="status">{msg}</div> : null;
  return [show, node];
}

const RTF = typeof Intl !== "undefined" && Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }) : null;

export function ago(ts) {
  if (!ts) return "never";
  const t = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
  const s = Math.round((t - Date.now()) / 1000);
  const abs = Math.abs(s);
  if (!RTF) return new Date(t).toLocaleString();
  if (abs < 45) return RTF.format(0, "second") === "now" ? "just now" : RTF.format(s, "second");
  if (abs < 3600) return RTF.format(Math.round(s / 60), "minute");
  if (abs < 86400) return RTF.format(Math.round(s / 3600), "hour");
  return RTF.format(Math.round(s / 86400), "day");
}

export function when(ts) {
  if (!ts) return "";
  const t = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
  return new Date(t).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}
