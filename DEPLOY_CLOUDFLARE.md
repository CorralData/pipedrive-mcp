# Deploying Pipedrive MCP to Cloudflare Containers

This deployment runs the Pipedrive MCP server as a Cloudflare Container, fronted by a small Worker that proxies all requests. Cloudflare Access secures the public URL.

## Architecture

```
claude.ai web
    |
    v  (HTTPS, with CF-Access-Client-Id + CF-Access-Client-Secret headers)
Cloudflare Access (auth gate)
    |
    v
Cloudflare Worker (pipedrive-mcp)
    |
    v  (durable-object container binding)
Cloudflare Container (running our Dockerfile, port 8152, FastMCP SSE)
    |
    v  (HTTPS)
api.pipedrive.com (using PIPEDRIVE_API_TOKEN)
```

## Files added by this deployment

- `wrangler.jsonc` — Cloudflare config: Worker name, container definition, durable-object binding for the container class
- `worker.ts` — Tiny Worker that forwards every request to the container instance
- `package.json` / `tsconfig.json` — TypeScript build config for the Worker
- `DEPLOY_CLOUDFLARE.md` — this file
- (existing) `Dockerfile` — already in repo, unchanged

## Prerequisites

- Cloudflare account with Workers Paid plan ($5/mo) — Containers require this
- A custom domain on Cloudflare (e.g. corraldata.com)
- Pipedrive API token + company subdomain

## Two deployment paths

### Path A: Workers Builds (browser-only, recommended)

Cloudflare Workers Builds connects a GitHub repo and auto-deploys on push.

1. Cloudflare dashboard → Workers & Pages → Create → Connect to Git
2. Authorize Cloudflare's GitHub app on the CorralData org → select `pipedrive-mcp` repo
3. Branch: `main`. Build command: leave empty (wrangler reads `wrangler.jsonc`). Deploy command: `npx wrangler deploy`
4. Click Create and Deploy
5. After first deploy, set Worker secrets (next section)

### Path B: wrangler CLI (one terminal command)

```bash
git clone https://github.com/CorralData/pipedrive-mcp.git
cd pipedrive-mcp
npm install
npx wrangler login         # opens browser
npx wrangler secret put PIPEDRIVE_API_TOKEN        # paste token
npx wrangler secret put PIPEDRIVE_COMPANY_DOMAIN   # paste subdomain
npx wrangler deploy
```

## Setting Worker secrets (both paths)

In the Cloudflare dashboard: Workers & Pages → pipedrive-mcp → Settings → Variables and Secrets → Add secret.

| Name | Value |
|---|---|
| `PIPEDRIVE_API_TOKEN` | Your Pipedrive API token (from Pipedrive: profile → Personal preferences → API → Generate new token) |
| `PIPEDRIVE_COMPANY_DOMAIN` | The subdomain part of your Pipedrive URL (e.g. `corraldata` from `corraldata.pipedrive.com`) |

## Custom domain + Cloudflare Access

1. Workers & Pages → pipedrive-mcp → Settings → Domains & Routes → Add → Custom domain → `pipedrive-mcp.corraldata.com`
2. Cloudflare Zero Trust → Access → Applications → Add an application → Self-hosted
   - Application domain: `pipedrive-mcp.corraldata.com`
   - Application type: Self-hosted
3. Add policy: Include → Service Token → (create new service token, save Client ID + Client Secret somewhere safe)
4. Optional: add a second policy that allows your Google Workspace identity (for browser debugging)

## Adding the connector in claude.ai

claude.ai → Settings → Connectors → Add custom connector

- URL: `https://pipedrive-mcp.corraldata.com/sse`
- Custom headers:
  - `CF-Access-Client-Id`: (from CF Access service token)
  - `CF-Access-Client-Secret`: (from CF Access service token)

Test with a prompt like "list my recent deals from Pipedrive".

## Cost estimate

- Workers Paid plan: $5/mo flat
- Container compute: billed per second of CPU + GB-second of memory while warm. With `sleepAfter = "5m"` and casual team use (a few sessions/day), expect well under $5/mo.
- Total expected: ~$5-15/mo depending on usage

## Updating

Pushes to `main` trigger automatic redeploy if using Path A. Otherwise rerun `npx wrangler deploy`.

