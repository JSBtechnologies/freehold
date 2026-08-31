# Freehold test app (`app.html`)

An interactive app that drives the real `@freehold/db` SDK against **this browser/device's actual
WebAuthn authenticator and OPFS** — the vehicle for the cross-browser/device matrix that the headless
Playwright specs (virtual authenticator) can't cover. Nothing leaves the device.

## Run locally
```
cd examples/demo
npm install         # first time (vite only)
npm run dev         # serves at http://localhost:5178
# open http://localhost:5178/app.html
```
`localhost` is a secure context, so passkeys + OPFS work in Chrome/Edge/Firefox without TLS.

## Test on a real phone / another device
WebAuthn requires a **secure context** (HTTPS or `localhost`) and the RP id must match the origin, so
a plain `http://<LAN-ip>` will not offer passkeys. Use one of:
- a tunnel that gives an HTTPS URL to your dev server (e.g. `cloudflared tunnel --url http://localhost:5178`
  or `ngrok http 5178`), then open the `https://…` URL on the device; or
- `vite --host` behind a locally-trusted TLS cert (mkcert) if you prefer to stay on the LAN.

## What to walk through (the matrix checklist)
1. **Preflight** — the capabilities panel should be all-green; note anything red (that's a platform gap).
2. **Enroll** — creates a platform passkey; confirm the OS passkey UI appears.
3. **Back up** — add a recovery code (shown once). Confirm "backup owed" clears.
4. **Unlock** — passkey assertion opens the session; add/refresh notes (encrypted SQLite via `sql()`).
5. **Methods** — add a second passkey; revoke one; confirm the survivors still open.
6. **Rotate** — revoke & re-encrypt; save the NEW recovery code; confirm old code/passkeys are refused.
7. **Export** — download `vault.freehold`; recover it with the standalone tool:
   `cargo run -p freehold-decrypt --release -- vault.freehold "YOUR-RECOVERY-CODE" ./out` → `out/app.sqlite`.
8. **Import** — load a bundle exported from another device and unlock it here.

A headless smoke of the enroll→backup→unlock→note path runs in `tests/app-smoke.spec.js`.
