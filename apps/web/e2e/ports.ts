// Ports for the end-to-end stack. Uncommon defaults so the suite doesn't collide with other local dev servers;
// override with KEYGUARD_E2E_API_PORT / KEYGUARD_E2E_WEB_PORT.
export const API_PORT = Number(process.env.KEYGUARD_E2E_API_PORT ?? 8917);
export const WEB_PORT = Number(process.env.KEYGUARD_E2E_WEB_PORT ?? 3917);
export const API_URL = `http://localhost:${API_PORT}`;
