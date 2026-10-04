// Dashboard load: N people with the dashboard open, each polling like the real page does
// (approvals every 3 s, audit + chain check every 5 s, overview every 15 s).
import http from "k6/http";
import { sleep } from "k6";
import { BASE, SMOKE, auth, ok } from "./lib.js";

const VUS = Number(__ENV.VUS || (SMOKE ? 5 : 50));

export const options = {
  scenarios: {
    dashboards: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: SMOKE
        ? [{ duration: "5s", target: VUS }, { duration: "10s", target: VUS }]
        : [{ duration: "30s", target: VUS }, { duration: "2m", target: VUS }, { duration: "20s", target: 0 }],
      gracefulRampDown: "10s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{endpoint:approvals}": ["p(95)<300"],
    "http_req_duration{endpoint:audit}": ["p(95)<500"],
    "http_req_duration{endpoint:audit_verify}": ["p(95)<1000"],
    "http_req_duration{endpoint:overview}": ["p(95)<1500"],
    "http_req_duration{endpoint:healthz}": ["p(95)<100"],
    checks: ["rate>0.99"],
  },
};

function get(path, endpoint) {
  const params = auth(__VU);
  params.tags = { endpoint };
  return ok(http.get(`${BASE}${path}`, params), endpoint);
}

export default function () {
  const tick = __ITER;
  if (tick === 0) {
    ok(http.get(`${BASE}/`, { tags: { endpoint: "page" } }), "page");
    get("/api/me", "me");
  }
  get("/api/approvals", "approvals");
  if (tick % 2 === 0) {
    get("/api/audit?limit=60", "audit");
    get("/api/audit/verify", "audit_verify");
  }
  if (tick % 5 === 0) get("/api/overview", "overview");
  ok(http.get(`${BASE}/healthz`, { tags: { endpoint: "healthz" } }), "healthz");
  sleep(3);
}
