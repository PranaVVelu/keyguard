// Same-origin proxy to the KeyGuard API (D-013). Active only when KEYGUARD_API_INTERNAL_URL and
// KEYGUARD_PROXY_SECRET are set (hosted on free subdomains); in local development the browser calls the API directly.

import type { NextRequest } from "next/server";

import {
  clientIpFrom,
  FORWARD_RESPONSE_HEADERS,
  forwardHeaders,
  isSafePath,
  MAX_BODY_BYTES,
  upstreamUrl,
} from "@/lib/proxy";

// Free API hosts sleep when idle and can take up to a minute to wake; give the first request time to get through.
export const maxDuration = 60;

const error = (status: number, code: string, message: string) =>
  Response.json({ error: { code, message } }, { status, headers: { "cache-control": "no-store" } });

async function handle(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  const base = process.env.KEYGUARD_API_INTERNAL_URL;
  const secret = process.env.KEYGUARD_PROXY_SECRET;
  if (!base || !secret) return error(404, "NOT_FOUND", "Request could not be served");

  const { path } = await ctx.params;
  if (!isSafePath(path)) return error(400, "REQUEST_INVALID", "Request failed validation");

  let body: ArrayBuffer | undefined;
  if (req.method === "POST") {
    body = await req.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) return error(413, "REQUEST_TOO_LARGE", "Request too large");
  }

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl(base, path, req.nextUrl.search), {
      method: req.method,
      headers: forwardHeaders(req.headers, secret, clientIpFrom(req.headers, process.env.KEYGUARD_CLIENT_IP_HEADER)),
      body,
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    return error(502, "API_UNREACHABLE", "The KeyGuard API is unreachable (it may be waking up; try again)");
  }

  const headers = new Headers();
  for (const name of FORWARD_RESPONSE_HEADERS) {
    const v = upstream.headers.get(name);
    if (v !== null) headers.set(name, v);
  }
  for (const cookie of upstream.headers.getSetCookie()) headers.append("set-cookie", cookie);
  return new Response(upstream.status === 204 ? null : upstream.body, { status: upstream.status, headers });
}

export const GET = handle;
export const POST = handle;
