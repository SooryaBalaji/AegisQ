// Approval race: two different people decide every pending approval at the same moment.
// Exactly one decision per approval may win (200); the other must get 409. Nothing else is allowed.
import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";
import exec from "k6/execution";
import { BASE, SMOKE, TOKENS, auth } from "./lib.js";

const IDS = JSON.parse(open(__ENV.APPROVALS_FILE || "./out/approvals.json"));
const wins = new Counter("decisions_won");
const conflicts = new Counter("decisions_conflict");
const unexpected = new Counter("decisions_unexpected");

if (TOKENS.length < 2) throw new Error("approvals.js needs at least two tokens (two approvers)");

export const options = {
  scenarios: {
    race: {
      executor: "shared-iterations",
      vus: Number(__ENV.VUS || (SMOKE ? 10 : 50)),
      iterations: IDS.length * 2,
      maxDuration: "5m",
    },
  },
  thresholds: {
    decisions_won: [`count==${IDS.length}`],
    decisions_conflict: [`count==${IDS.length}`],
    decisions_unexpected: ["count==0"],
    "http_req_duration{endpoint:decision}": ["p(95)<1000"],
  },
};

export default function () {
  const i = exec.scenario.iterationInTest;
  const id = IDS[Math.floor(i / 2)];
  const who = i % 2; // the two halves of each pair use different approvers
  const params = auth(who);
  params.headers["Content-Type"] = "application/json";
  params.tags = { endpoint: "decision" };
  const res = http.post(
    `${BASE}/api/approvals/${id}/decision`,
    JSON.stringify({ approve: who === 0, reason: `k6 race ${i}` }),
    params,
  );
  if (res.status === 200) wins.add(1);
  else if (res.status === 409) conflicts.add(1);
  else unexpected.add(1);
  check(res, { "decision: 200 or 409": (r) => r.status === 200 || r.status === 409 });
}

export function teardown() {
  const res = http.get(`${BASE}/api/approvals?status=pending`, auth(0));
  check(res, { "no approval left pending": (r) => r.status === 200 && r.json().length === 0 });
}
