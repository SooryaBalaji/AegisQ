// Token guessing under load. Pass criteria:
//   * no guessed token is ever accepted
//   * failures are throttled (429) after the limit (20 per client per 5 minutes)
//   * throttled replies stay cheap, and the unauthenticated health check keeps answering
// Note: the throttle is per client address, so legitimate users behind the same address are also
// blocked for the window. That is deliberate: letting valid tokens through while blocked would tell a
// blocked attacker which guess was right (200 vs 429) and make the throttle pointless.
import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";
import { BASE } from "./lib.js";

const DURATION = __ENV.SMOKE === "1" ? "5s" : "20s";
const rejected = new Counter("guesses_rejected_401");
const throttled = new Counter("guesses_throttled_429");
const leaked = new Counter("guesses_accepted");

export const options = {
  scenarios: {
    attacker: { executor: "constant-vus", vus: 20, duration: DURATION, exec: "guess" },
    health: { executor: "constant-arrival-rate", rate: 20, timeUnit: "1s", duration: DURATION, preAllocatedVUs: 5, exec: "health" },
  },
  thresholds: {
    guesses_accepted: ["count==0"],
    guesses_rejected_401: ["count<=20"],
    guesses_throttled_429: ["count>0"],
    "http_req_duration{endpoint:guess}": ["p(95)<100"],
    "http_req_failed{endpoint:healthz}": ["rate==0"],
    "http_req_duration{endpoint:healthz}": ["p(95)<100"],
  },
};

export function guess() {
  const token = `guess-${__VU}-${__ITER}-${Math.random().toString(36).slice(2)}`;
  const res = http.get(`${BASE}/api/me`, {
    headers: { Authorization: `Bearer ${token}` },
    tags: { endpoint: "guess" },
    responseCallback: http.expectedStatuses(401, 429),
  });
  if (res.status === 401) rejected.add(1);
  else if (res.status === 429) throttled.add(1);
  else leaked.add(1);
}

export function health() {
  const res = http.get(`${BASE}/healthz`, { tags: { endpoint: "healthz" } });
  check(res, { "healthz 200 during attack": (r) => r.status === 200 });
}
