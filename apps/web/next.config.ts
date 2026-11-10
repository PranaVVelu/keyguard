import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The Playwright suite builds into its own folder so it never overwrites the normal `.next` build.
  distDir: process.env.NEXT_DIST_DIR || ".next",
  cacheComponents: true,
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
