# BlackHeart Panel — Hostless Cloud (one-setting setup)

## The only manual deploy setting

Set the Hostless **Start Command** to:

    npm start

Everything else in this repository is configured by `hostless.yaml`:
- one replica (required for this file-backed panel);
- HTTP health check at `/health`;
- resource limits;
- automatic port binding through Hostless's `PORT` environment variable.

Use the repository root as the working directory. Keep Hostless's automatic Node.js build detection enabled. Do not manually set `PORT`.

## Open the panel

After deployment, open:

    https://YOUR-APP-DOMAIN/panel

The server listens on `0.0.0.0:$PORT`. Hostless provides public HTTPS.

## Important storage limitation

This one-setting edition stores panel state under `/tmp/blackheart-panel-data` so it can start without creating or attaching a volume. Hostless clears `/tmp` when an app process starts again. **Panel accounts/settings/configuration may therefore reset after a restart or redeployment.** This is the trade-off for not requiring a storage setting. If you need settings and credentials to survive restarts, a persistent volume must be attached separately at `/data` and `DATA_DIR=/data/panel-data` set as an environment variable; that is not possible to provision solely with the start command or `hostless.yaml`.

## Protocol limitation

Hostless Apps are HTTP services, not raw TCP proxy hosts. This build serves the panel and attempts WebSocket upgrades over Hostless HTTPS ingress. Verify WebSocket upgrade support with a real VLESS/Trojan client before relying on proxy traffic. Raw TCP listeners and the original TLS/TCP multiplexer are not available in this App deployment model.

## Security

Set a strong panel password during initial setup. Do not expose an unprotected admin panel publicly.
