export class AuthError extends Error {}

const sentence = (t) => (t ? t[0].toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? "" : ".") : t);

function detail(d, status) {
  if (Array.isArray(d)) return sentence(d.map((x) => `${(x.loc || []).slice(1).join(".") || "input"}: ${x.msg}`).join("; "));
  return sentence(d) || `Request failed (${status}).`;
}

export async function api(path, { method = "GET", body } = {}) {
  const headers = { "X-AegisQ": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/me/password")) {
    throw new AuthError("signed out");
  }
  if (res.status === 404 && method === "GET") return null;
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { msg = detail((await res.json()).detail, res.status); } catch { /* not JSON */ }
    throw new Error(msg);
  }
  const type = res.headers.get("content-type") || "";
  return type.includes("json") ? res.json() : res.text();
}

export async function download(path, filename) {
  const res = await fetch(path, { credentials: "same-origin" });
  if (res.status === 401) throw new AuthError("signed out");
  if (!res.ok) throw new Error(`Download failed (${res.status})`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function followJob(id, onLines, alive) {
  let since = 0;
  const lines = [];
  for (;;) {
    const d = await api(`/api/jobs/${encodeURIComponent(id)}?since=${since}`);
    if (!d) throw new Error("The job is no longer on the server.");
    if (d.log.length) {
      lines.push(...d.log);
      onLines(d.log);
    }
    since = d.since + d.log.length;
    if (d.status !== "running" || !alive()) return { ...d, lines };
    await sleep(700);
  }
}
