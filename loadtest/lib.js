// Shared helpers for the AegisQ k6 load tests.
import http from "k6/http";
import { check } from "k6";

export const BASE = __ENV.BASE_URL || "http://127.0.0.1:8000";
// USERS="alice:<password>,bob:<password>" - people who can sign in to the dashboard.
export const USERS = (__ENV.USERS || "").split(",").filter(Boolean).map((p) => {
  const i = p.indexOf(":");
  return { name: p.slice(0, i), password: p.slice(i + 1) };
});
if (USERS.length === 0) throw new Error("set USERS=name:password[,name:password...]");
export const JSON_HEADERS = { "Content-Type": "application/json", "X-AegisQ": "1" };

// Sign every user in once (call from setup()); returns their session ids.
export function signIn() {
  return USERS.map((u) => {
    const res = http.post(`${BASE}/api/login`, JSON.stringify({ name: u.name, password: u.password }), {
      headers: JSON_HEADERS,
    });
    check(res, { [`sign in ${u.name}: 200`]: (r) => r.status === 200 });
    return res.cookies.aegisq_session[0].value;
  });
}

// SMOKE=1 shrinks every scenario to a few seconds (CI); otherwise full size.
export const SMOKE = __ENV.SMOKE === "1";

export function auth(sessions, i = 0) {
  return { headers: { Cookie: `aegisq_session=${sessions[i % sessions.length]}`, "X-AegisQ": "1" } };
}

export function ok(res, name) {
  return check(res, { [`${name}: 200`]: (r) => r.status === 200 });
}
