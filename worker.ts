// Pipedrive MCP server - manual OAuth provider (no @cloudflare/workers-oauth-provider library)
// Architecture:
//   claude.ai -> /oauth/register (dynamic client registration)
//   claude.ai -> /.well-known/oauth-authorization-server (metadata discovery)
//   claude.ai -> /oauth/authorize -> redirects to CF Access OIDC
//   CF Access -> /oauth/callback -> issues our authorization code
//   claude.ai -> /oauth/token (exchanges code for access token, with PKCE)
//   claude.ai -> /sse, /messages (with Bearer token, forwards to container)

import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  PIPEDRIVE_MCP: DurableObjectNamespace<PipedriveMCPContainer>;
  PIPEDRIVE_API_TOKEN: string;
  PIPEDRIVE_COMPANY_DOMAIN: string;
  OIDC_CLIENT_ID: string;
  OIDC_CLIENT_SECRET: string;
  OIDC_ISSUER: string;
  OAUTH_KV: KVNamespace;
}

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

function json(data: any, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

async function sha256Base64Url(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---------- Landing page ----------
    if (path === "/") {
      return new Response(
        `<!doctype html><html><body style="font-family: system-ui; padding: 40px; max-width: 600px; margin: auto;">
          <h1>Pipedrive MCP</h1>
          <p>CorralData internal Pipedrive MCP server. Add to claude.ai with URL <code>${url.origin}/sse</code>.</p>
        </body></html>`,
        { headers: { "Content-Type": "text/html" } }
      );
    }

    // ---------- Debug: env var presence (no values exposed) ----------
    if (path === "/__debug") {
      return json({
        OIDC_CLIENT_ID_set: !!env.OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET_set: !!env.OIDC_CLIENT_SECRET,
        OIDC_ISSUER_set: !!env.OIDC_ISSUER,
        OIDC_ISSUER_value: env.OIDC_ISSUER || null, // not secret
        OIDC_CLIENT_ID_len: env.OIDC_CLIENT_ID?.length || 0,
        OIDC_CLIENT_SECRET_len: env.OIDC_CLIENT_SECRET?.length || 0,
        PIPEDRIVE_API_TOKEN_set: !!env.PIPEDRIVE_API_TOKEN,
        PIPEDRIVE_COMPANY_DOMAIN_set: !!env.PIPEDRIVE_COMPANY_DOMAIN,
        PIPEDRIVE_COMPANY_DOMAIN_value: env.PIPEDRIVE_COMPANY_DOMAIN || null,
        OAUTH_KV_set: !!env.OAUTH_KV,
        PIPEDRIVE_MCP_set: !!env.PIPEDRIVE_MCP,
      });
    }

    // ---------- OAuth metadata discovery ----------
    if (path === "/.well-known/oauth-authorization-server") {
      return json({
        issuer: url.origin,
        authorization_endpoint: `${url.origin}/oauth/authorize`,
        token_endpoint: `${url.origin}/oauth/token`,
        registration_endpoint: `${url.origin}/oauth/register`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code"],
        token_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "email", "profile"],
      });
    }

    if (path === "/.well-known/oauth-protected-resource" || path.startsWith("/.well-known/oauth-protected-resource/")) {
      return json({
        resource: url.origin,
        authorization_servers: [url.origin],
        bearer_methods_supported: ["header"],
      });
    }

    // ---------- Dynamic client registration ----------
    if (path === "/oauth/register" && request.method === "POST") {
      let body: any;
      try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((u: any) => typeof u === "string") : [];
      if (redirectUris.length === 0) return json({ error: "invalid_redirect_uri" }, 400);
      const clientId = crypto.randomUUID();
      await env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify({
        redirectUris,
        clientName: typeof body.client_name === "string" ? body.client_name : null,
        registeredAt: Math.floor(Date.now() / 1000),
      }), { expirationTtl: 365 * 86400 });
      return json({
        client_id: clientId,
        redirect_uris: redirectUris,
        client_name: body.client_name || null,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_id_issued_at: Math.floor(Date.now() / 1000),
      }, 201);
    }

    // ---------- Authorize: redirect to CF Access OIDC ----------
    if (path === "/oauth/authorize") {
      try {
        const p = url.searchParams;
        const clientId = p.get("client_id") || "";
        const redirectUri = p.get("redirect_uri") || "";
        const state = p.get("state") || "";
        const codeChallenge = p.get("code_challenge") || "";
        const codeChallengeMethod = p.get("code_challenge_method") || "";
        const responseType = p.get("response_type") || "";
        const scope = p.get("scope") || "openid email profile";

        if (responseType !== "code") return new Response("Only response_type=code supported", { status: 400 });
        if (!clientId || !redirectUri) return new Response("Missing client_id or redirect_uri", { status: 400 });

        // Verify client exists
        const clientStr = await env.OAUTH_KV.get(`client:${clientId}`);
        if (!clientStr) return new Response("Unknown client", { status: 400 });
        const client = JSON.parse(clientStr);

        // Permissive redirect_uri check: must be in registered list (string match)
        if (!client.redirectUris.includes(redirectUri)) {
          return new Response(`redirect_uri not registered. Registered: ${JSON.stringify(client.redirectUris)}, requested: ${redirectUri}`, { status: 400 });
        }

        // Sanity-check OIDC env vars
        if (!env.OIDC_ISSUER || !env.OIDC_CLIENT_ID) {
          return new Response(`Server misconfigured: OIDC_ISSUER_set=${!!env.OIDC_ISSUER} OIDC_CLIENT_ID_set=${!!env.OIDC_CLIENT_ID}`, { status: 500 });
        }

        // Persist the original request keyed by an upstream state UUID
        const upstreamState = crypto.randomUUID();
        await env.OAUTH_KV.put(`upstream:${upstreamState}`, JSON.stringify({
          clientId, redirectUri, state, codeChallenge, codeChallengeMethod, scope,
        }), { expirationTtl: 600 });

        // Redirect to CF Access OIDC authorize
        // OIDC_ISSUER may have a trailing slash; strip it
        const issuer = env.OIDC_ISSUER.replace(/\/$/, "");
        const cfAuth = new URL(`${issuer}/cdn-cgi/access/sso/oidc/${env.OIDC_CLIENT_ID}/authorization`);
        cfAuth.searchParams.set("response_type", "code");
        cfAuth.searchParams.set("client_id", env.OIDC_CLIENT_ID);
        cfAuth.searchParams.set("redirect_uri", `${url.origin}/oauth/callback`);
        cfAuth.searchParams.set("scope", "openid email profile");
        cfAuth.searchParams.set("state", upstreamState);
        return Response.redirect(cfAuth.toString(), 302);
      } catch (e: any) {
        return new Response(`/oauth/authorize error: ${e?.message || e}\nStack: ${e?.stack || "n/a"}`, { status: 500 });
      }
    }

    // ---------- Callback from CF Access ----------
    if (path === "/oauth/callback") {
      const code = url.searchParams.get("code");
      const upstreamState = url.searchParams.get("state");
      if (!code || !upstreamState) return new Response("Missing code or state", { status: 400 });

      const stored = await env.OAUTH_KV.get(`upstream:${upstreamState}`);
      if (!stored) return new Response("State expired or unknown", { status: 400 });
      const reqInfo = JSON.parse(stored);
      await env.OAUTH_KV.delete(`upstream:${upstreamState}`);

      // Exchange CF Access code for ID token
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
        return new Response(`OIDC token exchange failed (${tokenRes.status}): ${errText}`, { status: 502 });
      }
      const tokenData: any = await tokenRes.json();
      let userEmail = "unknown";
      try {
        const payload = JSON.parse(atob(tokenData.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
        userEmail = payload.email || payload.sub || "unknown";
      } catch {}

      // Issue our authorization code, store the user info + PKCE
      const authCode = crypto.randomUUID() + "-" + crypto.randomUUID();
      await env.OAUTH_KV.put(`code:${authCode}`, JSON.stringify({
        clientId: reqInfo.clientId,
        redirectUri: reqInfo.redirectUri,
        codeChallenge: reqInfo.codeChallenge,
        codeChallengeMethod: reqInfo.codeChallengeMethod,
        scope: reqInfo.scope,
        userEmail,
      }), { expirationTtl: 600 });

      // Redirect back to claude.ai
      const callback = new URL(reqInfo.redirectUri);
      callback.searchParams.set("code", authCode);
      if (reqInfo.state) callback.searchParams.set("state", reqInfo.state);
      return Response.redirect(callback.toString(), 302);
    }

    // ---------- Token endpoint: exchange auth code for access token ----------
    if (path === "/oauth/token" && request.method === "POST") {
      let formData: FormData;
      try { formData = await request.formData(); } catch { return json({ error: "invalid_request" }, 400); }
      const grantType = formData.get("grant_type") as string;

      if (grantType === "authorization_code") {
        const code = formData.get("code") as string;
        const codeVerifier = formData.get("code_verifier") as string;
        const redirectUri = formData.get("redirect_uri") as string;
        const clientId = formData.get("client_id") as string;

        if (!code) return json({ error: "invalid_request" }, 400);
        const stored = await env.OAUTH_KV.get(`code:${code}`);
        if (!stored) return json({ error: "invalid_grant", error_description: "Code not found or expired" }, 400);
        const codeInfo = JSON.parse(stored);
        await env.OAUTH_KV.delete(`code:${code}`);

        if (clientId && clientId !== codeInfo.clientId) return json({ error: "invalid_grant", error_description: "Client mismatch" }, 400);
        if (redirectUri && redirectUri !== codeInfo.redirectUri) return json({ error: "invalid_grant", error_description: "Redirect mismatch" }, 400);

        // Verify PKCE
        if (codeInfo.codeChallenge) {
          if (!codeVerifier) return json({ error: "invalid_grant", error_description: "Missing code_verifier" }, 400);
          if (codeInfo.codeChallengeMethod === "S256") {
            const calc = await sha256Base64Url(codeVerifier);
            if (calc !== codeInfo.codeChallenge) return json({ error: "invalid_grant", error_description: "PKCE failed" }, 400);
          } else {
            if (codeVerifier !== codeInfo.codeChallenge) return json({ error: "invalid_grant", error_description: "PKCE failed" }, 400);
          }
        }

        const accessToken = crypto.randomUUID() + crypto.randomUUID();
        const expiresIn = 30 * 86400;
        await env.OAUTH_KV.put(`token:${accessToken}`, JSON.stringify({
          clientId: codeInfo.clientId,
          userEmail: codeInfo.userEmail,
          scope: codeInfo.scope,
          issuedAt: Math.floor(Date.now() / 1000),
        }), { expirationTtl: expiresIn });

        return json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: expiresIn,
          scope: codeInfo.scope,
        });
      }

      return json({ error: "unsupported_grant_type" }, 400);
    }

    // ---------- API routes (protected by Bearer) ----------
    if (path === "/sse" || path.startsWith("/sse/") || path.startsWith("/messages")) {
      const authHeader = request.headers.get("Authorization") || "";
      if (!authHeader.startsWith("Bearer ")) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer realm="oauth", resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`,
          },
        });
      }
      const token = authHeader.substring(7);
      const stored = await env.OAUTH_KV.get(`token:${token}`);
      if (!stored) {
        return new Response("Invalid token", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer realm="oauth", error="invalid_token", resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`,
          },
        });
      }
      // Forward to the container
      const container = getContainer(env.PIPEDRIVE_MCP, "singleton");
      return container.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
