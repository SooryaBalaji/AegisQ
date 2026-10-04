const TOKEN_KEY = "aegisq-token";

export class AuthError extends Error {}

export function loadToken() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function saveToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* private mode */ }
}

export function makeApi(token) {
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
    });
    if (res.status === 401) throw new AuthError("unauthorized");
    if (res.status === 404) return null;
    if (!res.ok) {
      let msg = `${res.status}`;
      try {
        const d = (await res.json()).detail;
        if (Array.isArray(d)) msg = d.map((x) => `${(x.loc || []).slice(1).join(".") || "input"}: ${x.msg}`).join("; ");
        else if (d) msg = d;
      } catch { /* not json */ }
      throw new Error(msg);
    }
    const type = res.headers.get("content-type") || "";
    return type.includes("json") ? res.json() : res.text();
  }

  async function download(path, filename) {
    const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) { alert(`Download failed (${res.status})`); return; }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return { api, download };
}

export async function startJob(client, payload, loadJobs, signOut) {
  try {
    const job = await client.api("/api/jobs", { method: "POST", body: JSON.stringify(payload) });
    await loadJobs();
    return job;
  } catch (e) {
    if (e instanceof AuthError) signOut("Your token was rejected.");
    else alert(`Could not start: ${e.message}`);
    return null;
  }
}
