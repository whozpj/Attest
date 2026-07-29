// Local concurrency/load probe against a running Human-Attest server.
// Not a CI-gated test -- SQLite (this project's storage engine) is
// single-writer by design, so the interesting question isn't "how many
// requests/sec" but "does concurrent write contention ever produce wrong
// results," which src/api/state.race.test.ts already covers at the unit
// level. This script instead measures real HTTP-layer latency under
// concurrent load and confirms the server stays correct (every attestation
// created is independently readable back) while under it.
//
// Usage: BASE=http://localhost:3000 npx tsx scripts/load-test.mts [concurrency] [total]
//
// Defaults (concurrency=10, total=25) are deliberately sized to fit inside
// this server's own per-route rate limits (Task 3): POST /v1/principals is
// capped at 10/minute and POST /v1/attestations at 30/minute
// (src/api/routes.principals.ts, src/api/routes.attestations.ts). An
// earlier draft of this script created one throwaway principal per
// attestation and defaulted to total=200 -- running it for real against the
// live server immediately surfaced 429s from the principal-creation limit,
// which then produced a null approver_id and a 400 on attestation creation.
// That's the rate limiter (an intentional, already-shipped protection
// against enrolment spam/enumeration) doing its job, not something this
// probe should route around -- so the fix is to create exactly one shared
// approver principal up front, outside the timed loop, and drive the
// concurrent load entirely at POST /v1/attestations, which is what this
// probe actually intends to measure. Raise `total` past ~30 only alongside
// a longer wall-clock run (the limit is per rolling minute, not per run).

const BASE = process.env.BASE ?? "http://localhost:3000";
const CONCURRENCY = Number(process.argv[2] ?? 10);
const TOTAL = Number(process.argv[3] ?? 25);

async function createApproverPrincipal(): Promise<string> {
  const res = await fetch(`${BASE}/v1/principals`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: `load-${crypto.randomUUID()}@test.local`, display_name: "Load Test" }),
  });
  if (res.status !== 201) throw new Error(`unexpected status ${res.status} creating approver principal`);
  const body = await res.json();
  return body.principal_id;
}

async function createAttestation(approverId: string): Promise<number> {
  const start = performance.now();
  const res = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "load-test", approver_ids: [approverId],
      action: { type: "generic", risk_tier: "low", payload: { title: "Load test", detail: "x" } },
    }),
  });
  if (res.status !== 201) throw new Error(`unexpected status ${res.status}`);
  const body = await res.json();

  const readback = await fetch(`${BASE}/v1/attestations/${body.attestation_id}`).then((r) => r.json());
  if (readback.attestation_id !== body.attestation_id || readback.status !== "pending") {
    throw new Error(`readback mismatch for ${body.attestation_id}`);
  }

  return performance.now() - start;
}

async function worker(approverId: string, latencies: number[], remaining: { count: number }): Promise<void> {
  while (remaining.count > 0) {
    remaining.count--;
    latencies.push(await createAttestation(approverId));
  }
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

const approverId = await createApproverPrincipal();

const latencies: number[] = [];
const remaining = { count: TOTAL };
const started = performance.now();
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker(approverId, latencies, remaining)));
const elapsed = performance.now() - started;

const sorted = [...latencies].sort((a, b) => a - b);
console.log(`\n${TOTAL} attestations created and read back correctly, concurrency=${CONCURRENCY}`);
console.log(`  total wall time:  ${elapsed.toFixed(0)}ms`);
console.log(`  throughput:       ${(TOTAL / (elapsed / 1000)).toFixed(1)} attestations/sec`);
console.log(`  latency p50:      ${percentile(sorted, 50).toFixed(1)}ms`);
console.log(`  latency p95:      ${percentile(sorted, 95).toFixed(1)}ms`);
console.log(`  latency p99:      ${percentile(sorted, 99).toFixed(1)}ms`);
console.log(`  latency max:      ${sorted[sorted.length - 1].toFixed(1)}ms`);
