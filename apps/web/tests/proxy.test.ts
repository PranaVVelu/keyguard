import assert from "node:assert/strict";
import { test } from "node:test";

import { clientIpFrom, forwardHeaders, isSafePath, upstreamUrl } from "../lib/proxy.ts";

test("only plain path segments are proxied", () => {
  assert.ok(isSafePath(["labs", "lab_AAAAAAAAAAAAAAAAAAAAAA", "vehicles"]));
  for (const bad of [[], [".."], ["labs", ".."], ["a%2Fb"], ["a/b"], [""], ["evil.example"], ["x".repeat(65)], Array(9).fill("a")]) {
    assert.equal(isSafePath(bad), false, JSON.stringify(bad));
  }
});

test("the upstream URL always stays on the configured API origin", () => {
  const u = upstreamUrl("https://keyguard-api.onrender.com/ignored/path", ["labs", "x"], "?q=1");
  assert.equal(u.toString(), "https://keyguard-api.onrender.com/api/labs/x?q=1");
  assert.throws(() => upstreamUrl("file:///etc/passwd", ["labs"], ""));
});

test("client IP comes from the platform header, falling back to the first X-Forwarded-For hop", () => {
  assert.equal(clientIpFrom(new Headers({ "x-real-ip": "198.51.100.1", "x-forwarded-for": "6.6.6.6" })), "198.51.100.1");
  assert.equal(clientIpFrom(new Headers({ "x-forwarded-for": "198.51.100.2, 10.0.0.1" })), "198.51.100.2");
  assert.equal(clientIpFrom(new Headers()), "");
  assert.equal(clientIpFrom(new Headers({ "cf-connecting-ip": "203.0.113.4" }), "cf-connecting-ip"), "203.0.113.4");
});

test("only allow-listed headers are forwarded, and client-sent proxy headers are replaced", () => {
  const incoming = new Headers({
    authorization: "Bearer t",
    "content-type": "application/json",
    cookie: "kg_session=abc",
    "x-keyguard-csrf": "1",
    "x-keyguard-proxy-secret": "forged",
    "x-keyguard-client-ip": "1.2.3.4",
    "x-forwarded-for": "6.6.6.6",
    host: "evil.example",
  });
  const out = forwardHeaders(incoming, "real-secret", "198.51.100.9");
  assert.equal(out.get("authorization"), "Bearer t");
  assert.equal(out.get("cookie"), "kg_session=abc");
  assert.equal(out.get("x-keyguard-csrf"), "1");
  assert.equal(out.get("x-keyguard-proxy-secret"), "real-secret");
  assert.equal(out.get("x-keyguard-client-ip"), "198.51.100.9");
  assert.equal(out.get("x-forwarded-for"), null);
  assert.equal(out.get("host"), null);
});
