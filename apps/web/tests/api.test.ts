import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { ApiError, createLab, getVehicles } from "../lib/api.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function stub(status: number, body: unknown, headers: Record<string, string> = {}) {
  globalThis.fetch = async () => new Response(JSON.stringify(body), { status, headers });
}

test("a 429 surfaces the stable code and how long to wait", async () => {
  stub(429, { error: { code: "RATE_LIMITED", message: "Too many requests" } }, { "Retry-After": "12" });
  await assert.rejects(createLab(), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 429);
    assert.equal(e.code, "RATE_LIMITED");
    assert.equal(e.message, "Too many requests; try again in 12 s");
    return true;
  });
});

test("a non-numeric Retry-After is ignored rather than echoed", async () => {
  stub(429, { error: { code: "RATE_LIMITED", message: "Too many requests" } }, { "Retry-After": "<script>" });
  await assert.rejects(createLab(), { message: "Too many requests" });
});

test("the bearer token is sent only in the Authorization header", async () => {
  let seen: { url: string; auth: string | null } | null = null;
  globalThis.fetch = async (input, init) => {
    seen = { url: String(input), auth: new Headers(init?.headers).get("Authorization") };
    return new Response(JSON.stringify({ vehicles: [] }), { status: 200 });
  };
  await getVehicles({ labId: "lab_x", labToken: "secret-token", expiresAt: 0 });
  assert.equal(seen!.auth, "Bearer secret-token");
  assert.ok(!seen!.url.includes("secret-token"));
});

test("an unreachable API becomes NETWORK_ERROR", async () => {
  globalThis.fetch = async () => {
    throw new TypeError("fetch failed");
  };
  await assert.rejects(createLab(), { code: "NETWORK_ERROR" });
});
