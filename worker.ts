// Pipedrive MCP - pure Cloudflare Worker (no container)
// - OAuth provider for claude.ai (PKCE, dynamic registration, CF Access OIDC backend)
// - MCP server (Streamable HTTP transport) that calls Pipedrive REST API directly
// Architecture:
//   claude.ai -> /oauth/register (dynamic client registration)
//   claude.ai -> /.well-known/oauth-authorization-server (metadata discovery)
//   claude.ai -> /oauth/authorize -> redirects to CF Access OIDC
//   CF Access -> /oauth/callback -> issues our authorization code
//   claude.ai -> /oauth/token (exchanges code for access token, with PKCE)
//   claude.ai -> /sse (POST JSON-RPC, Bearer protected) -> handled in-worker

interface Env {
  PIPEDRIVE_API_TOKEN: string;
  PIPEDRIVE_COMPANY_DOMAIN: string;
  OIDC_CLIENT_ID: string;
 OIDC_CLIENT_SECRET: string;
  OIDC_ISSUER: string;
  OAUTH_KV: KVNamespace;
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

async function logEvent(env: Env, event: Record<string, any>) {
  try {
    const log = await env.OAUTH_KV.get("__debug_log");
    const events = log ? JSON.parse(log) : [];
    events.unshift({ ts: new Date().toISOString(), ...event });
    await env.OAUTH_KV.put("__debug_log", JSON.stringify(events.slice(0, 50)), { expirationTtl: 86400 });
  } catch {}
}

// ============================================================================
// Pipedrive API helpers
// ============================================================================

async function pdFetch(env: Env, method: string, path: string, body?: any): Promise<any> {
  const url = new URL(`https://${env.PIPEDRIVE_COMPANY_DOMAIN}.pipedrive.com/v1${path}`);
  url.searchParams.set("api_token", env.PIPEDRIVE_API_TOKEN);
  const init: RequestInit = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) init.body = JSON.stringify(body);
  const res = await fetch(url.toString(), init);
  const text = await res.text();
  let data: any;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  if (!res.ok) {
    return { error: true, status: res.status, body: data };
  }
  return data;
}

// ============================================================================
// MCP tools
// ============================================================================

const TOOLS = [
  {
    name: "search_deals",
    description: "Search for deals in Pipedrive by free-text term. Returns matching deals.",
    inputSchema: {
      type: "object",
      properties: {
        term: { type: "string", description: "Search term (deal name or part of it). Required, min 2 chars." },
        limit: { type: "number", description: "Max results (default 20, max 500).", default: 20 },
      },
      required: ["term"],
    },
  },
  {
    name: "get_deal",
    description: "Get full details of a Pipedrive deal by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Deal ID." } },
      required: ["id"],
    },
  },
  {
    name: "list_deals",
    description: "List Pipedrive deals with optional filters. Use 'status' to filter by all_not_deleted/open/won/lost/deleted. Use 'user_id' to filter by deal owner.",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "all_not_deleted (default), open, won, lost, or deleted." },
        user_id: { type: "number", description: "Filter by owner user_id." },
        limit: { type: "number", description: "Max results (default 50, max 500).", default: 50 },
        start: { type: "number", description: "Pagination start (default 0).", default: 0 },
      },
    },
  },
  {
    name: "create_deal",
    description: "Create a new Pipedrive deal. Returns the created deal.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Deal title. Required." },
        value: { type: "number", description: "Deal value (number)." },
        currency: { type: "string", description: "Currency code (e.g. USD)." },
        person_id: { type: "number", description: "Linked person ID." },
        org_id: { type: "number", description: "Linked organization ID." },
        stage_id: { type: "number", description: "Pipeline stage ID." },
        user_id: { type: "number", description: "Owner user ID." },
        status: { type: "string", description: "open, won, lost, or deleted." },
      },
      required: ["title"],
    },
  },
  {
    name: "update_deal",
    description: "Update fields on an existing Pipedrive deal. Pass only the fields to change.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Deal ID to update." },
        title: { type: "string" },
        value: { type: "number" },
        currency: { type: "string" },
        person_id: { type: "number" },
        org_id: { type: "number" },
        stage_id: { type: "number" },
        user_id: { type: "number" },
        status: { type: "string" },
        label: { type: "number", description: "Label ID to set on the deal (single value; see GET /dealFields for available label option IDs)." },
      },
      required: ["id"],
    },
  },
  {
    name: "search_persons",
    description: "Search for persons (contacts) by name, email, or phone.",
    inputSchema: {
      type: "object",
      properties: {
        term: { type: "string", description: "Search term. Required, min 2 chars." },
        fields: { type: "string", description: "Comma-separated fields to search: name, email, phone, custom_fields. Default: name,email,phone." },
        limit: { type: "number", default: 20 },
      },
      required: ["term"],
    },
  },
  {
    name: "get_person",
    description: "Get full details of a Pipedrive person by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Person ID." } },
      required: ["id"],
    },
  },
  {
    name: "create_person",
    description: "Create a new person (contact). Returns the created person.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Person name. Required." },
        email: { type: "string", description: "Primary email address." },
        phone: { type: "string", description: "Primary phone number." },
        org_id: { type: "number", description: "Linked organization ID." },
        owner_id: { type: "number", description: "Owner user ID." },
      },
      required: ["name"],
    },
  },
  {
    name: "search_organizations",
    description: "Search for organizations by name.",
    inputSchema: {
      type: "object",
      properties: {
        term: { type: "string", description: "Search term. Required, min 2 chars." },
        limit: { type: "number", default: 20 },
      },
      required: ["term"],
    },
  },
  {
    name: "get_organization",
    description: "Get full details of an organization by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Organization ID." } },
      required: ["id"],
    },
  },
  {
    name: "create_organization",
    description: "Create a new organization.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Organization name. Required." },
        owner_id: { type: "number", description: "Owner user ID." },
      },
      required: ["name"],
    },
  },
  {
    name: "list_pipelines",
    description: "List all Pipedrive pipelines.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "list_stages",
    description: "List Pipedrive stages, optionally filtered by pipeline_id.",
    inputSchema: {
      type: "object",
      properties: {
        pipeline_id: { type: "number", description: "Filter by pipeline ID (optional)." },
      },
    },
  },
  {
    name: "list_users",
    description: "List all Pipedrive users.",
    inputSchema: { type: "object", properties: {} },
  },
  { name: "list_deal_fields", description: "List Pipedrive deal fields, including the Label field's available options (id + label text) needed for setting a deal's label via update_deal.", inputSchema: { type: "object", properties: {} } },
  {
    name: "add_note",
    description: "Add a note to a deal, person, or organization.",
    inputSchema: {
      type: "object",
      properties: {
        content: { type: "string", description: "Note content (HTML supported). Required." },
        deal_id: { type: "number", description: "Attach to deal." },
        person_id: { type: "number", description: "Attach to person." },
        org_id: { type: "number", description: "Attach to organization." },
      },
      required: ["content"],
    },
  },
  {
    name: "add_activity",
    description: "Add an activity (task, call, meeting, etc.) optionally linked to a deal/person/org.",
    inputSchema: {
      type: "object",
      properties: {
        subject: { type: "string", description: "Activity subject/title. Required." },
        type: { type: "string", description: "Activity type key (e.g. 'call', 'meeting', 'task'). Default: 'task'." },
        due_date: { type: "string", description: "YYYY-MM-DD." },
        due_time: { type: "string", description: "HH:MM (24h)." },
        duration: { type: "string", description: "HH:MM duration." },
        deal_id: { type: "number" },
        person_id: { type: "number" },
        org_id: { type: "number" },
        user_id: { type: "number" },
        done: { type: "number", description: "0=not done, 1=done." },
        note: { type: "string", description: "Activity note/body." },
      },
      required: ["subject"],
    },
  },
  {
    name: "list_activities",
    description: "List/find activities in Pipedrive. Optionally filter by done status or owner. For a specific deal's activities, pass deal_id.",
    inputSchema: {
      type: "object",
      properties: {
        done: { type: "number", description: "Filter by completion: 0=not done, 1=done. Omit for all." },
        user_id: { type: "number", description: "Filter by owner user_id." },
        deal_id: { type: "number", description: "Return activities for this deal instead of all activities." },
        limit: { type: "number", description: "Max results (default 100, max 500).", default: 100 },
        start: { type: "number", description: "Pagination start (default 0).", default: 0 },
      },
    },
  },
  {
    name: "get_activity",
    description: "Get full details of a single Pipedrive activity by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Activity ID." } },
      required: ["id"],
    },
  },
  {
    name: "update_activity",
    description: "Update fields on an existing Pipedrive activity, e.g. mark it done or add a note. Pass only the fields to change.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Activity ID to update. Required." },
        done: { type: "number", description: "0=not done, 1=done." },
        subject: { type: "string" },
        note: { type: "string" },
        due_date: { type: "string", description: "YYYY-MM-DD." },
        due_time: { type: "string", description: "HH:MM (24h)." },
        type: { type: "string" },
      },
      required: ["id"],
    },
  },
];

async function callTool(env: Env, name: string, args: Record<string, any>): Promise<any> {
  switch (name) {
    case "search_deals": {
      const q = new URLSearchParams({ term: String(args.term), limit: String(args.limit ?? 20) });
      return pdFetch(env, "GET", `/deals/search?${q}`);
    }
    case "get_deal":
      return pdFetch(env, "GET", `/deals/${args.id}`);
    case "list_deals": {
      const q = new URLSearchParams();
      q.set("status", String(args.status ?? "all_not_deleted"));
      if (args.user_id !== undefined) q.set("user_id", String(args.user_id));
      q.set("limit", String(args.limit ?? 50));
      q.set("start", String(args.start ?? 0));
      return pdFetch(env, "GET", `/deals?${q}`);
    }
    case "create_deal":
      return pdFetch(env, "POST", `/deals`, args);
    case "update_deal": {
      const { id, ...body } = args;
      return pdFetch(env, "PUT", `/deals/${id}`, body);
    }
    case "search_persons": {
      const q = new URLSearchParams({ term: String(args.term), limit: String(args.limit ?? 20) });
      if (args.fields) q.set("fields", String(args.fields));
      return pdFetch(env, "GET", `/persons/search?${q}`);
    }
    case "get_person":
      return pdFetch(env, "GET", `/persons/${args.id}`);
    case "create_person": {
      const body: any = { name: args.name };
      if (args.email) body.email = [args.email];
      if (args.phone) body.phone = [args.phone];
      if (args.org_id) body.org_id = args.org_id;
      if (args.owner_id) body.owner_id = args.owner_id;
      return pdFetch(env, "POST", `/persons`, body);
    }
    case "search_organizations": {
      const q = new URLSearchParams({ term: String(args.term), limit: String(args.limit ?? 20) });
      return pdFetch(env, "GET", `/organizations/search?${q}`);
    }
    case "get_organization":
      return pdFetch(env, "GET", `/organizations/${args.id}`);
    case "create_organization":
      return pdFetch(env, "POST", `/organizations`, args);
    case "list_pipelines":
      return pdFetch(env, "GET", `/pipelines`);
    case "list_stages": {
      const q = new URLSearchParams();
      if (args.pipeline_id !== undefined) q.set("pipeline_id", String(args.pipeline_id));
      const qs = q.toString();
      return pdFetch(env, "GET", `/stages${qs ? "?" + qs : ""}`);
    }
    case "list_users":
      return pdFetch(env, "GET", `/users`);
    case "list_deal_fields":
      return pdFetch(env, "GET", `/dealFields`);
    case "add_note": {
      const body: any = { content: args.content };
      if (args.deal_id) body.deal_id = args.deal_id;
      if (args.person_id) body.person_id = args.person_id;
      if (args.org_id) body.org_id = args.org_id;
      return pdFetch(env, "POST", `/notes`, body);
    }
    case "add_activity": {
      const body: any = {
        subject: args.subject,
        type: args.type ?? "task",
      };
      for (const k of ["due_date", "due_time", "duration", "deal_id", "person_id", "org_id", "user_id", "done", "note"]) {
        if (args[k] !== undefined) body[k] = args[k];
      }
      return pdFetch(env, "POST", `/activities`, body);
    }
    case "list_activities": {
      const q = new URLSearchParams();
      if (args.done !== undefined) q.set("done", String(args.done));
      if (args.user_id !== undefined) q.set("user_id", String(args.user_id));
      q.set("limit", String(args.limit ?? 100));
      q.set("start", String(args.start ?? 0));
      const base = args.deal_id !== undefined ? `/deals/${args.deal_id}/activities` : `/activities`;
      return pdFetch(env, "GET", `${base}?${q}`);
    }
    case "get_activity":
      return pdFetch(env, "GET", `/activities/${args.id}`);
    case "update_activity": {
      const { id, ...body } = args;
      return pdFetch(env, "PUT", `/activities/${id}`, body);
    }
    default:
      return { error: true, message: `Unknown tool: ${name}` };
  }
}

// ============================================================================
// MCP JSON-RPC handler (Streamable HTTP transport)
// ============================================================================

async function handleMcp(env: Env, req: any): Promise<any | null> {
  const { jsonrpc, id, method, params } = req;
  if (jsonrpc !== "2.0") {
    return { jsonrpc: "2.0", id: id ?? null, error: { code: -32600, message: "Invalid Request: jsonrpc must be 2.0" } };
  }

  // Notifications (no id) get no response
  const isNotification = id === undefined || id === null;

  if (method === "initialize") {
    return {
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "pipedrive-mcp", version: "2.0.0" },
      },
    };
  }

  if (method === "notifications/initialized" || method === "initialized") {
    return null; // notification, no response
  }

  if (method === "tools/list") {
    return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  }

  if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments ?? {};
    if (!name) return { jsonrpc: "2.0", id, error: { code: -32602, message: "Missing tool name" } };
    try {
      const result = await callTool(env, name, args);
      return {
        jsonrpc: "2.0", id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          isError: !!(result && (result as any).error),
        },
      };
    } catch (e: any) {
      return {
        jsonrpc: "2.0", id,
        result: {
          content: [{ type: "text", text: `Tool execution error: ${e?.message || String(e)}` }],
          isError: true,
        },
      };
    }
  }

  if (method === "ping") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (isNotification) return null;
  return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
}

// ============================================================================
// Worker fetch handler
// ============================================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Landing page
    if (path === "/") {
      return new Response(
        `<!doctype html><html><body style="font-family: system-ui; padding: 40px; max-width: 600px; margin: auto;">
          <h1>Pipedrive MCP</h1>
          <p>CorralData internal Pipedrive MCP server. Add to claude.ai with URL <code>${url.origin}/sse</code>.</p>
          <p>Pure-Worker implementation. No container.</p>
        </body></html>`,
        { headers: { "Content-Type": "text/html" } }
      );
    }

    // Debug
    if (path === "/__debug/log") {
      const log = await env.OAUTH_KV.get("__debug_log");
      return json(log ? JSON.parse(log) : []);
    }
    if (path === "/__debug/clear") {
      await env.OAUTH_KV.delete("__debug_log");
      return json({ cleared: true });
    }
    if (path === "/__debug") {
      return json({
        OIDC_CLIENT_ID_set: !!env.OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET_set: !!env.OIDC_CLIENT_SECRET,
        OIDC_ISSUER_value: env.OIDC_ISSUER || null,
        OIDC_CLIENT_SECRET_len: env.OIDC_CLIENT_SECRET?.length || 0,
        PIPEDRIVE_API_TOKEN_set: !!env.PIPEDRIVE_API_TOKEN,
        PIPEDRIVE_COMPANY_DOMAIN_value: env.PIPEDRIVE_COMPANY_DOMAIN || null,
        OAUTH_KV_set: !!env.OAUTH_KV,
      });
    }

    // OAuth metadata
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

    // Dynamic client registration
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

    // Authorize -> CF Access OIDC
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

        const clientStr = await env.OAUTH_KV.get(`client:${clientId}`);
        if (!clientStr) return new Response("Unknown client", { status: 400 });
        const client = JSON.parse(clientStr);
        if (!client.redirectUris.includes(redirectUri)) {
          return new Response(`redirect_uri not registered`, { status: 400 });
        }

        if (!env.OIDC_ISSUER || !env.OIDC_CLIENT_ID) {
          return new Response(`Server misconfigured`, { status: 500 });
        }

        const upstreamState = crypto.randomUUID();
        await env.OAUTH_KV.put(`upstream:${upstreamState}`, JSON.stringify({
          clientId, redirectUri, state, codeChallenge, codeChallengeMethod, scope,
        }), { expirationTtl: 600 });

        const issuer = env.OIDC_ISSUER.replace(/\/$/, "");
        const cfAuth = new URL(`${issuer}/cdn-cgi/access/sso/oidc/${env.OIDC_CLIENT_ID}/authorization`);
        cfAuth.searchParams.set("response_type", "code");
        cfAuth.searchParams.set("client_id", env.OIDC_CLIENT_ID);
        cfAuth.searchParams.set("redirect_uri", `${url.origin}/oauth/callback`);
        cfAuth.searchParams.set("scope", "openid email profile");
        cfAuth.searchParams.set("state", upstreamState);
        return Response.redirect(cfAuth.toString(), 302);
      } catch (e: any) {
        return new Response(`/oauth/authorize error: ${e?.message || e}`, { status: 500 });
      }
    }

    // Callback from CF Access
    if (path === "/oauth/callback") {
      const code = url.searchParams.get("code");
      const upstreamState = url.searchParams.get("state");
      if (!code || !upstreamState) return new Response("Missing code or state", { status: 400 });

      const stored = await env.OAUTH_KV.get(`upstream:${upstreamState}`);
      if (!stored) return new Response("State expired or unknown", { status: 400 });
      const reqInfo = JSON.parse(stored);
      await env.OAUTH_KV.delete(`upstream:${upstreamState}`);

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

      const authCode = crypto.randomUUID() + "-" + crypto.randomUUID();
      await env.OAUTH_KV.put(`code:${authCode}`, JSON.stringify({
        clientId: reqInfo.clientId,
        redirectUri: reqInfo.redirectUri,
        codeChallenge: reqInfo.codeChallenge,
        codeChallengeMethod: reqInfo.codeChallengeMethod,
        scope: reqInfo.scope,
        userEmail,
      }), { expirationTtl: 600 });

      const callback = new URL(reqInfo.redirectUri);
      callback.searchParams.set("code", authCode);
      if (reqInfo.state) callback.searchParams.set("state", reqInfo.state);
      return Response.redirect(callback.toString(), 302);
    }

    // Token exchange
    if (path === "/oauth/token" && request.method === "POST") {
      let formData: FormData;
      try { formData = await request.formData(); } catch {
        return json({ error: "invalid_request" }, 400);
      }
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

    // MCP endpoint (protected by Bearer)
    if (path === "/sse" || path.startsWith("/sse/") || path.startsWith("/messages") || path === "/mcp") {
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

      // GET with text/event-stream Accept (legacy SSE client probe). Return an empty stream that
      // emits an endpoint event then closes — claude.ai will fall back to Streamable HTTP POST.
      if (request.method === "GET") {
        return new Response("", {
          status: 405,
          headers: {
            "Allow": "POST",
            "Content-Type": "text/plain",
          },
        });
      }

      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
      }

      let body: any;
      try { body = await request.json(); } catch {
        return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
      }

      // Body can be a single request or an array (batch)
      if (Array.isArray(body)) {
        const results = await Promise.all(body.map(req => handleMcp(env, req)));
        const filtered = results.filter(r => r !== null);
        if (filtered.length === 0) return new Response(null, { status: 202 });
        return json(filtered);
      } else {
        const result = await handleMcp(env, body);
        if (result === null) return new Response(null, { status: 202 });
        await logEvent(env, { ep: "/sse", method: body?.method, ok: !result.error });
        return json(result);
      }
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
