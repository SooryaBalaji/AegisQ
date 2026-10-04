export const STATUS = {
  pq_ready: ["good", "PQ ready"], classical: ["warning", "Classical"], tls12_only: ["serious", "TLS 1.2 only"],
  legacy_tls: ["critical", "Legacy TLS"], plaintext: ["critical", "Plaintext"], unreachable: ["muted", "Unreachable"],
  error: ["muted", "Error"],
};
export const SEV = { critical: "critical", high: "serious", medium: "warning", low: "muted", none: "good", unknown: "muted" };
export const JOB_STATUS = { running: ["warning", "running"], succeeded: ["good", "done"], failed: ["critical", "failed"], cancelled: ["muted", "cancelled"] };

export const fmt = (n, d = 1) => (n === null || n === undefined ? "–" : Number(n).toFixed(d));
export const years = (v) => `${fmt(Math.abs(v), Math.abs(v) % 1 ? 1 : 0)} year${Math.abs(v) === 1 ? "" : "s"}`;

export function Badge({ kind, children, className = "" }) {
  return <span className={`badge s-${kind} ${className}`.trim()}>{children}</span>;
}

export function severity(margin, status) {
  if (status === "pq_ready") return "none";
  if (status === "plaintext") return "critical";
  if (status === "unreachable" || status === "error") return "unknown";
  if (margin >= 10) return "critical";
  if (margin > 0) return "high";
  if (margin > -5) return "medium";
  return "low";
}

export const marginOf = (r, z) => r.x + r.y - (r.status === "plaintext" ? 0 : z);

export function why(r) {
  if (r.status === "pq_ready") return "Protected: completes a post-quantum handshake.";
  if (r.status === "plaintext") return "No encryption at all: readable today.";
  if (r.status === "unreachable" || r.status === "error") return "Could not connect, so the risk is unknown.";
  return r.margin > 0 ? `Exposed: data outlives the guess by ${years(r.margin)}.` : `Safe for now: ${years(r.margin)} to spare.`;
}

export function duration(j) {
  const s = Math.round((j.finished || Date.now() / 1000) - j.created);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}
