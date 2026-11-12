import type { NextConfig } from "next";

// Security headers for production builds (docs/DECISIONS.md D-013). Development is left alone so hot reload
// (which needs eval and websockets) keeps working; the Playwright suite runs a production build, so every e2e
// test exercises this policy.
// NEXT_PUBLIC_API_URL empty or "same-origin" means same-origin proxy mode: the browser only ever talks to this origin.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const API_ORIGIN = API_URL && API_URL !== "same-origin" ? new URL(API_URL).origin : "";

export const CSP = [
  "default-src 'self'",
  // Next.js App Router inlines its bootstrap scripts; a nonce-based policy needs dynamic rendering (follow-up).
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  // The only place this page may send data: itself and the KeyGuard API. Blocks exfiltration to other hosts.
  `connect-src 'self'${API_ORIGIN ? ` ${API_ORIGIN}` : ""}`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

function securityHeaders() {
  const headers = [
    { key: "Content-Security-Policy", value: CSP },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "no-referrer" },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()" },
  ];
  if (process.env.KEYGUARD_HSTS === "1") {
    headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" });
  }
  return headers;
}

const nextConfig: NextConfig = {
  // The Playwright suite builds into its own folder so it never overwrites the normal `.next` build.
  distDir: process.env.NEXT_DIST_DIR || ".next",
  cacheComponents: true,
  poweredByHeader: false,
  async headers() {
    if (process.env.NODE_ENV !== "production") return [];
    return [{ source: "/:path*", headers: securityHeaders() }];
  },
  partialPrefetching: true,
  // Pin the workspace root so a stray lockfile in a parent folder can't change how the app is built.
  outputFileTracingRoot: import.meta.dirname,
  turbopack: {
    root: import.meta.dirname,
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
