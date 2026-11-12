import assert from "node:assert/strict";
import { test } from "node:test";

import { describeReason, eventLabel, eventQueryString, MAX_SEARCH_LENGTH, PAGE_SIZE, percent } from "../lib/events.ts";

test("query string drops empty filters and always sets a page size", () => {
  assert.equal(eventQueryString({}), `?limit=${PAGE_SIZE}`);
  assert.equal(eventQueryString({ category: "", result: "", q: "   " }), `?limit=${PAGE_SIZE}`);
});

test("query string encodes filters, search and paging", () => {
  const qs = new URLSearchParams(
    eventQueryString({ category: "authentication", result: "fail", reason: "KEY_REVOKED", q: " a&b=c ", offset: 50 }).slice(1),
  );
  assert.equal(qs.get("category"), "authentication");
  assert.equal(qs.get("result"), "fail");
  assert.equal(qs.get("reason"), "KEY_REVOKED");
  assert.equal(qs.get("q"), "a&b=c"); // trimmed and safely encoded, not split into extra params
  assert.equal(qs.get("offset"), "50");
  assert.equal([...qs.keys()].length, 6);
});

test("search text is capped to what the API accepts", () => {
  const qs = new URLSearchParams(eventQueryString({ q: "x".repeat(200) }).slice(1));
  assert.equal(qs.get("q")!.length, MAX_SEARCH_LENGTH);
});

test("event labels and reason descriptions", () => {
  assert.equal(eventLabel("authenticate_unlock"), "Authenticate · unlock");
  assert.equal(eventLabel("authenticate"), "Authenticate");
  assert.equal(eventLabel("key_revoked"), "Key revoked");
  assert.equal(eventLabel("scenario_replay"), "Scenario · replay");
  assert.equal(eventLabel("mystery"), "mystery");
  assert.equal(eventLabel("fob_unlock"), "Fob press · unlock");
  assert.match(describeReason("COUNTER_REPLAYED"), /replay/i);
  assert.match(describeReason("CHALLENGE_CONSUMED"), /replay/i);
  assert.equal(describeReason("SOMETHING_NEW"), "SOMETHING_NEW"); // unknown codes shown verbatim
});

test("percent handles zero totals", () => {
  assert.equal(percent(0, 0), 0);
  assert.equal(percent(1, 3), 33);
  assert.equal(percent(2, 2), 100);
});
