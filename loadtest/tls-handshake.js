// TLS handshake load against the demo fleet: a fresh connection per request, so every request pays a
// full handshake. k6's Go TLS stack offers X25519MLKEM768 first, so the PQ server negotiates the hybrid
// and the classical server falls back to X25519 - the same thing browsers do.
import http from "k6/http";
import { check } from "k6";
import { SMOKE } from "./lib.js";

const PQ = __ENV.PQ_URL || "https://127.0.0.1:8446/";
const CLASSICAL = __ENV.CLASSICAL_URL || "https://127.0.0.1:8443/";
const RATE = Number(__ENV.RATE || (SMOKE ? 20 : 200));
const DURATION = SMOKE ? "10s" : "1m";

function scenario(target) {
  return {
    executor: "constant-arrival-rate",
    rate: RATE,
    timeUnit: "1s",
    duration: DURATION,
    preAllocatedVUs: 20,
    maxVUs: 200,
    exec: "hit",
    env: { TARGET: target },
    tags: { target: target === PQ ? "pq" : "classical" },
  };
}

export const options = {
  insecureSkipTLSVerify: true, // demo certificates; we measure handshakes, not trust
  noConnectionReuse: true,
  scenarios: { pq: scenario(PQ), classical: scenario(CLASSICAL) },
  thresholds: {
    "http_req_failed{target:pq}": ["rate<0.01"],
    "http_req_failed{target:classical}": ["rate<0.01"],
    "http_req_tls_handshaking{target:pq}": ["p(95)<50"],
    "http_req_tls_handshaking{target:classical}": ["p(95)<50"],
    dropped_iterations: ["count<10"],
  },
};

export function hit() {
  const res = http.get(__ENV.TARGET);
  check(res, { "status 200": (r) => r.status === 200, "TLS 1.3": (r) => r.tls_version === "tls1.3" });
}
