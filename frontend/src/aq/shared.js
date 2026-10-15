export const STATUS = {
  pq_ready: "Post-quantum ready",
  classical: "Classical key exchange",
  tls12_only: "TLS 1.2 only",
  legacy_tls: "Legacy TLS",
  plaintext: "Plaintext",
  unreachable: "Unreachable",
  error: "Error",
};

export const SCANNED = /^\s*scanned (.+): ([a-z0-9_]+)\s*$/;

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function follow(api, id, onLines, alive) {
  let since = 0;
  const lines = [];
  for (;;) {
    const d = await api(`/api/jobs/${encodeURIComponent(id)}?since=${since}`);
    if (!d) throw new Error("The job disappeared from the server.");
    if (d.log.length) {
      lines.push(...d.log);
      onLines(d.log);
    }
    since = d.since + d.log.length;
    if (d.status !== "running" || !alive()) return { ...d, lines };
    await sleep(700);
  }
}
