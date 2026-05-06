// Pipedrive MCP server with OAuth provider, fronted by Cloudflare Workers.
// Architecture:
//   claude.ai → /sse                 (protected by OAuth)
//   claude.ai → /oauth/authorize     (redirects user to CF Access OIDC)
//                ↓
//             CF Access logs user in (via configured IdP: email OTP, Google, etc.)
//                ↓
//             /oauth/callback         (exchanges OIDC code → issues MCP token)
//                ↓
//             claude.ai gets the MCP token and uses it for /sse + /messages

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  // Container binding
  PIPEDRIVE_MCP: DurableObjectNamespace<PipedriveMCPContainer>;
  // Pipedrive credentials (passed into container)
  PIPEDRIVE_API_TOKEN: string;
  PIPEDRIVE_COMPANY_DOMAIN: string;
  // CF Access OIDC SaaS app credentials (Worker secrets)
  OIDC_CLIENT_ID: string;
  OIDC_CLIENT_SECRET: string;
  OIDC_ISSUER: string; // e.g. https://corraldata-co.cloudflareaccess.com
  // KV for OAuth provider state (workers-oauth-provider uses this internally)
  OAUTH_KV: KVNamespace;
}

// ---------- Container class (Pipedrive MCP server in a container) ----------
export class PipedriveMCPContainer extends Container<Env> {
  defaultPort = 8152;
  sleepAfter = "5m";

  override get envVars() {
    return {
      HOST: "0.0.0.0",
      PORT: "8152",
      TRANSPORT: "sse",
      CONTAINER_MODE: "true",
      PIPEDRIVE_API_TOKEN: this.env.PIPEDRIVE_API_TOKEN,
      PIPEDRIVE_COMPANY_DOMAIN: this.env.PIPEDRIVE_COMPANY_DOMAIN,
    };
  }
}

// ---------- API handler: forwards authenticated requests to container ----------
// OAuthProvider validates the bearer token before requests reach this handler.
const apiHandler: ExportedHandler<Env> = {
  async fetch(request, env): Promise<Response> {
    const container = getContainer(env.PIPEDRIVE_MCP, "singleton");
    return container.fetch(request);
  },
};

// ---------- Default handler: OAuth flow + CF Access OIDC bridge ----------
// Implements:
//   GET  /oauth/authorize  → redirect user to CF Access OIDC for login
//   GET  /oauth/callback   → exchange OIDC code, then call provider.completeAuthorization()
//   GET  /                 → friendly landing page for humans

const defaultHandler: ExportedHandler<Env> = {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    // Friendly landing page
    if (url.pathname === "/") {
      return new Response(
        `<!doctype html><html><body style="font-family: system-ui; padding: 40px; max-width: 600px; margin: auto;">
          <h1>Pipedrive MCP</h1>
          <p>This is the CorralData internal Pipedrive MCP server. Add it to claude.ai as a custom connector with URL <code>${url.origin}/sse</code>.</p>
        </body></html>`,
        { headers: { "Content-Type": "text/html" } }
      );
    }

    // OAuth authorize: claude.ai sends user here. We redirect to CF Access OIDC.
    if (url.pathname === "/oauth/authorize") {
      // Forward all of claude.ai's OAuth params to the OAuth provider so it
      // can store the request. Then we redirect the user to CF Access.
      let oauthReqInfo: any; try { oauthReqInfo = await (env as any).OAUTH_PROVIDER.parseAuthRequest(request); } catch (e: any) { return new Response("DEBUG parseAuthRequest threw: " + (e?.name||"") + ": " + (e?.message||"") + "\nstack: " + (e?.stack||"") + "\nOIDC_ISSUER=" + env.OIDC_ISSUER + "\nOIDC_CLIENT_ID_set=" + !!env.OIDC_CLIENT_ID, { status: 500, headers: { "Content-Type": "text/plain" } }); }
      // Build CF Access OIDC authorize URL
      const upstreamState = crypto.randomUUID();
      // Persist mapping: upstreamState → original OAuth request (for callback)
      await env.OAUTH_KV.put(
        `upstream:${upstreamState}`,
        JSON.stringify(oauthReqInfo),
        { expirationTtl: 600 }
      );
      const cfAuthorize = new URL(`${env.OIDC_ISSUER}/cdn-cgi/access/sso/oidc/${env.OIDC_CLIENT_ID}/authorization`);
      cfAuthorize.searchParams.set("response_type", "code");
      cfAuthorize.searchParams.set("client_id", env.OIDC_CLIENT_ID);
      cfAuthorize.searchParams.set("redirect_uri", `${url.origin}/oauth/callback`);
      cfAuthorize.searchParams.set("scope", "openid email profile");
      cfAuthorize.searchParams.set("state", upstreamState);
      return Response.redirect(cfAuthorize.toString(), 302);
    }

    // OAuth callback: CF Access redirects here with auth code.
    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code");
      const upstreamState = url.searchParams.get("state");
      if (!code || !upstreamState) {
        return new Response("Missing code or state", { status: 400 });
      }
      // Look up the original claude.ai OAuth request
      const stored = await env.OAUTH_KV.get(`upstream:${upstreamState}`);
      if (!stored) return new Response("State mismatch or expired", { status: 400 });
      const oauthReqInfo = JSON.parse(stored);
      await env.OAUTH_KV.delete(`upstream:${upstreamState}`);

      // Exchange code for ID token at CF Access
      const tokenRes = await fetch(`${env.OIDC_ISSUER}/cdn-cgi/access/sso/oidc/${env.OIDC_CLIENT_ID}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: `${url.origin}/oauth/callback`,
          client_id: env.OIDC_CLIENT_ID,
          client_secret: env.OIDC_CLIENT_SECRET,
        }),
      });
      if (!tokenRes.ok) {
        const errText = await tokenRes.text();
        return new Response(`OIDC token exchange failed: ${errText}`, { status: 502 });
      }
      const tokenJson: any = await tokenRes.json();
      const idToken: string = tokenJson.id_token;
      // Decode ID token (we trust CF Access's response since we just got it over HTTPS from them)
      const payload = JSON.parse(atob(idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      const userId = payload.email || payload.sub;

      // Issue MCP-OAuth code via the provider, redirect back to claude.ai
      const { redirectTo } = await (env as any).OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId,
        metadata: { email: payload.email, name: payload.name },
        scope: oauthReqInfo.scope,
        props: { email: payload.email },
      });
      return Response.redirect(redirectTo, 302);
    }

    return new Response("Not found", { status: 404 });
  },
};

// ---------- Wire it all together ----------
export default new OAuthProvider({
  apiRoute: ["/sse", "/messages"],
  apiHandler: apiHandler as any,
  defaultHandler: defaultHandler as any,
  authorizeEndpoint: "/oauth/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
});
