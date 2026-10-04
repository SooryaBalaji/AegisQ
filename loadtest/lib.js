// Shared helpers for the AegisQ k6 load tests.
import { check } from "k6";

export const BASE = __ENV.BASE_URL || "http://127.0.0.1:8000";
// TOKENS="alice:<token>,bob:<token>" - the same format as AEGISQ_API_TOKENS.
export const TOKENS = (__ENV.TOKENS || "").split(",").filter(Boolean).map((p) => {
  const i = p.indexOf(":");
  return { name: p.slice(0, i), token: p.slice(i + 1) };
});
if (TOKENS.length === 0) throw new Error("set TOKENS=name:token[,name:token...]");

// SMOKE=1 shrinks every scenario to a few seconds (CI); otherwise full size.
export const SMOKE = __ENV.SMOKE === "1";

export function auth(i = 0) {
  return { headers: { Authorization: `Bearer ${TOKENS[i % TOKENS.length].token}` } };
}

export function ok(res, name) {
  return check(res, { [`${name}: 200`]: (r) => r.status === 200 });
}
