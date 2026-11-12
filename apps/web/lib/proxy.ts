// Same-origin API proxy for free-subdomain hosting (docs/DECISIONS.md D-013).
// The browser calls /api/* on the web app's own origin; the server forwards to the API with a shared secret and
// the visitor's IP. Pure helpers live here so the security-relevant parts are unit-tested (tests/proxy.test.ts).

/** Request headers the API needs. Everything else (including any client-sent X-KeyGuard-* headers) is dropped. */
export const FORWARD_REQUEST_HEADERS = ["authorization", "content-type", "cookie", "x-keyguard-csrf"] as const;
/** Response headers passed back to the browser. Set-Cookie is handled separately (it can repeat). */
export const FORWARD_RESPONSE_HEADERS = ["content-type", "retry-after", "cache-control"] as const;
export const MAX_BODY_BYTES = 64 * 1024; // the largest real request (a passkey response) is a few KB

const SEGMENT = /^[A-Za-z0-9_-]{1,64}$/;

/** Only plain path segments: no "..", "%2F", empty segments or anything that could point the fetch elsewhere. */
export function isSafePath(segments: readonly string[]): boolean {
  return segments.length > 0 && segments.length <= 8 && segments.every((s) => SEGMENT.test(s));
}

/** Upstream URL, always on the configured API origin. Throws if the base isn't an http(s) origin. */
export function upstreamUrl(base: string, segments: readonly string[], search: string): URL {
  const origin = new URL(base);
  if (origin.protocol !== "https:" && origin.protocol !== "http:") throw new Error("API base must be http(s)");
  const url = new URL(`/api/${segments.join("/")}`, origin.origin);
  url.search = search;
  return url;
}

/** The visitor's IP as reported by the hosting platform's edge (which overwrites any client-supplied value). */
export function clientIpFrom(headers: Headers, headerName = "x-real-ip"): string {
  const direct = headers.get(headerName)?.trim();
  if (direct) return direct;
  return headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "";
}

export function forwardHeaders(incoming: Headers, secret: string, clientIp: string): Headers {
  const out = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const v = incoming.get(name);
    if (v !== null) out.set(name, v);
  }
  out.set("x-keyguard-proxy-secret", secret);
  if (clientIp) out.set("x-keyguard-client-ip", clientIp);
  return out;
}
