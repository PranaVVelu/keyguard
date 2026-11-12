// Ports and mode for the end-to-end stack. Uncommon default ports so the suite doesn't collide with other local
// dev servers; override with KEYGUARD_E2E_API_PORT / KEYGUARD_E2E_WEB_PORT.
//
// KEYGUARD_E2E_MODE=proxy runs the whole suite the way free-subdomain hosting works (D-013): the browser only
// talks to the web origin, whose /api/* route forwards to the API with a shared secret.
export const API_PORT = Number(process.env.KEYGUARD_E2E_API_PORT ?? 8917);
export const WEB_PORT = Number(process.env.KEYGUARD_E2E_WEB_PORT ?? 3917);
export const PROXY_MODE = process.env.KEYGUARD_E2E_MODE === "proxy";
/** The API server itself (for checks that must bypass the web app). */
export const API_DIRECT_URL = `http://localhost:${API_PORT}`;
/** What page scripts use to reach the API: their own origin in proxy mode. */
export const API_URL = PROXY_MODE ? "" : API_DIRECT_URL;
