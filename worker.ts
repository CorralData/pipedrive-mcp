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
  ZENDESK_WEBHOOK_SECRET: string;
  ZENDESK_API_TOKEN: string;
  PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET: string;
}

const ZENDESK_SUBDOMAIN = "corraldata";
const ZENDESK_AGENT_EMAIL = "alex@corraldata.com";

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
// Zendesk API helper
// ============================================================================

async function zendeskFetch(env: Env, method: string, path: string, body?: any): Promise<any> {
  const url = `https://${ZENDESK_SUBDOMAIN}.zendesk.com${path}`;
  const auth = btoa(`${ZENDESK_AGENT_EMAIL}/token:${env.ZENDESK_API_TOKEN}`);
  const init: RequestInit = {
    method,
    headers: { "Content-Type": "application/json", "Authorization": `Basic ${auth}` },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  const res = await fetch(url, init);
  const text = await res.text();
  let data: any;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  if (!res.ok) {
    return { error: true, status: res.status, body: data };
  }
  return data;
}

// Find the Pipedrive activity linked to a Zendesk ticket. Fast path: a KV mapping written
// when the activity was created (see /webhooks/zendesk). Fallback for activities created
// before that mapping existed: paginate not-done activities and match the
// "Zendesk ticket #<id>:" marker in the subject client-side. Note: Pipedrive's search APIs
// (/searchResults is gone, /itemSearch explicitly rejects item_types=activity) can't do this
// server-side, so this is the only reliable approach.
async function findActivityForTicket(env: Env, ticketId: string): Promise<number | null> {
  const mapped = await env.OAUTH_KV.get(`ticket_activity:${ticketId}`);
  if (mapped) return Number(mapped);
  const marker = `#${ticketId}:`;
  for (let start = 0; start < 2500; start += 500) {
    const res = await pdFetch(env, "GET", `/activities?${new URLSearchParams({ done: "0", limit: "500", start: String(start) })}`);
    const items = Array.isArray(res?.data) ? res.data : [];
    for (const act of items) {
      if (typeof act?.subject === "string" && act.subject.includes(marker)) {
        return act.id;
      }
    }
    if (items.length < 500) break;
  }
  return null;
}

// Given a search term (email), find the Pipedrive person whose primary or listed
// email address exactly (case-insensitively) matches. Returns null if no exact match,
// rather than falling back to a fuzzy/first result (avoids mismatching to unrelated contacts).
async function findPersonByExactEmail(env: Env, email: string): Promise<any | null> {
  const target = email.trim().toLowerCase();
  const searchRes = await pdFetch(
    env,
    "GET",
    `/persons/search?${new URLSearchParams({ term: email, fields: "email", limit: "10" })}`
  );
  const items = searchRes?.data?.items || [];
  for (const it of items) {
    const person = it.item;
    if (!person) continue;
    const emails: string[] = [];
    if (person.primary_email) emails.push(person.primary_email);
    if (Array.isArray(person.emails)) emails.push(...person.emails);
    if (emails.some((e: string) => String(e).trim().toLowerCase() === target)) {
      return person;
    }
  }
  return null;
}

// Find the Pipedrive user (agent) whose email exactly matches the given address, so
// synced activities can be assigned to whoever the Zendesk ticket is actually assigned to
// instead of defaulting to the API token owner. Caches the user list in KV for 10 minutes
// since /users is a small, slow-changing list and this runs on every webhook call.
async function findPipedriveUserByEmail(env: Env, email: string): Promise<any | null> {
  const target = email.trim().toLowerCase();
  if (!target) return null;
  let users: any[] | null = null;
  const cached = await env.OAUTH_KV.get("pd_users_cache");
  if (cached) {
    try { users = JSON.parse(cached); } catch {}
  }
  if (!users) {
    const res = await pdFetch(env, "GET", "/users");
    users = Array.isArray(res?.data) ? res.data : [];
    await env.OAUTH_KV.put("pd_users_cache", JSON.stringify(users), { expirationTtl: 600 });
  }
  return users.find((u: any) => String(u?.email || "").trim().toLowerCase() === target) || null;
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
  { name: "update_deal_field", description: "Update a Pipedrive deal field's options (e.g. add new Label options). IMPORTANT: options must be the FULL desired list - any existing option you omit will be deleted. Fetch current options via list_deal_fields first, then pass that full array plus your new option(s) appended (new options omit 'id').", inputSchema: { type: "object", properties: { id: { type: "number", description: "Deal field ID (e.g. the Label field's id from list_deal_fields). Required." }, options: { type: "array", description: "Full array of option objects: { id?: number, label: string, color?: string }.", items: { type: "object", properties: { id: { type: "number" }, label: { type: "string" }, color: { type: "string" } }, required: ["label"] } } }, required: ["id", "options"] } },
  { name: "update_organization", description: "Update fields on an existing Pipedrive organization, including custom fields (pass the custom field's hashed key as a property - see the key returned by create_organization_field). Pass only the fields to change.", inputSchema: { type: "object", properties: { id: { type: "number", description: "Organization ID to update. Required." }, name: { type: "string" }, owner_id: { type: "number" } }, required: ["id"], additionalProperties: true } },
  { name: "create_organization_field", description: "Create a new custom field on Organizations (e.g. a Renewal Date field). Returns the created field including its 'key' - use that key as a property name when calling update_organization to set values on organizations.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Field name, e.g. 'Renewal Date'. Required." }, field_type: { type: "string", description: "Pipedrive field type: date, varchar, text, double, enum, etc. Required." } }, required: ["name", "field_type"] } },
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
    name: "list_notes",
    description: "List notes in Pipedrive, optionally filtered by deal_id, person_id, or org_id. Use before delete_note to find the note's ID.",
    inputSchema: {
      type: "object",
      properties: {
        deal_id: { type: "number", description: "Filter to notes on this deal." },
        person_id: { type: "number", description: "Filter to notes on this person." },
        org_id: { type: "number", description: "Filter to notes on this organization." },
        start: { type: "number", description: "Pagination start (default 0).", default: 0 },
        limit: { type: "number", description: "Max results (default 100, max 500).", default: 100 },
      },
    },
  },
  {
    name: "get_note",
    description: "Get full details of a single Pipedrive note by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Note ID." } },
      required: ["id"],
    },
  },
  {
    name: "delete_note",
    description: "Permanently delete a note from Pipedrive by ID. This cannot be undone - use list_notes first to confirm the correct note ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Note ID to delete. Required." } },
      required: ["id"],
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
  {
    name: "create_webhook",
    description: "Create a Pipedrive webhook subscription. Pipedrive will POST to subscription_url whenever event_object/event_action occurs (e.g. object='activity', action='change').",
    inputSchema: {
      type: "object",
      properties: {
        subscription_url: { type: "string", description: "Full URL Pipedrive should POST to. Required." },
        event_action: { type: "string", description: "Pipedrive v2 naming: create, change, delete, or *. Required." },
        event_object: { type: "string", description: "e.g. activity, deal, person, or *. Required." },
        http_auth_user: { type: "string", description: "Optional HTTP basic auth username Pipedrive will send." },
        http_auth_password: { type: "string", description: "Optional HTTP basic auth password Pipedrive will send." },
      },
      required: ["subscription_url", "event_action", "event_object"],
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
    case "update_organization": { const { id, ...body } = args; return pdFetch(env, "PUT", `/organizations/${id}`, body); }
    case "create_organization_field": return pdFetch(env, "POST", `/organizationFields`, args);
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
    case "update_deal_field": {
      const { id, ...body } = args;
      return pdFetch(env, "PUT", `/dealFields/${id}`, body);
    }
    case "add_note": {
      const body: any = { content: args.content };
      if (args.deal_id) body.deal_id = args.deal_id;
      if (args.person_id) body.person_id = args.person_id;
      if (args.org_id) body.org_id = args.org_id;
      return pdFetch(env, "POST", `/notes`, body);
    }
    case "list_notes": {
      const q = new URLSearchParams();
      if (args.deal_id !== undefined) q.set("deal_id", String(args.deal_id));
      if (args.person_id !== undefined) q.set("person_id", String(args.person_id));
      if (args.org_id !== undefined) q.set("org_id", String(args.org_id));
      q.set("start", String(args.start ?? 0));
      q.set("limit", String(args.limit ?? 100));
      return pdFetch(env, "GET", `/notes?${q}`);
    }
    case "get_note":
      return pdFetch(env, "GET", `/notes/${args.id}`);
    case "delete_note":
      return pdFetch(env, "DELETE", `/notes/${args.id}`);
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
    case "create_webhook":
      return pdFetch(env, "POST", `/webhooks`, args);
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
    if (path === "/webhooks/zendesk" && request.method === "POST") { const secret = url.searchParams.get("secret") || ""; if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) { return new Response("Unauthorized", { status: 401 }); } let payload: any = {}; try { payload = await request.json(); } catch { return json({ error: "invalid_json" }, 400); } const ticketId = payload.ticket_id; const subject = payload.subject || "Zendesk ticket"; const email = payload.requester_email; const ticketUrl = payload.ticket_url; const personMatch = email ? await findPersonByExactEmail(env, String(email)) : null; const assigneeEmail = payload.assignee_email; const assigneeUserMatch = assigneeEmail ? await findPipedriveUserByEmail(env, String(assigneeEmail)) : null; const activityBody: any = { subject: `Zendesk ticket #${ticketId}: ${subject}`, type: "task", note: `${ticketUrl || ""} - Requester: ${payload.requester_name || ""} <${email || ""}>` }; if (personMatch) { activityBody.person_id = personMatch.id; const orgId = (personMatch.organization && personMatch.organization.id) || personMatch.org_id; if (orgId) activityBody.org_id = orgId; } if (assigneeUserMatch) { activityBody.user_id = assigneeUserMatch.id; } const result = await pdFetch(env, "POST", "/activities", activityBody); if (result && result.data && result.data.id) { await env.OAUTH_KV.put(`ticket_activity:${ticketId}`, String(result.data.id)); } await logEvent(env, { ep: "/webhooks/zendesk", ticketId, matched: !!personMatch, ok: !(result && result.error) }); return json({ ok: !(result && result.error), matched: !!personMatch }); }

    // Forward sync: Zendesk ticket marked solved/closed -> mark the linked Pipedrive activity done.
    // Uses findActivityForTicket (KV mapping written at activity-creation time, with a
    // paginated-scan fallback for activities that predate that mapping).
    if (path === "/webhooks/zendesk/solved" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      let payload: any = {};
      try { payload = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
      const ticketId = payload.ticket_id;
      if (!ticketId) return json({ error: "missing_ticket_id" }, 400);
      const matchedActivityId = await findActivityForTicket(env, String(ticketId));
      if (!matchedActivityId) {
        await logEvent(env, { ep: "/webhooks/zendesk/solved", ticketId, matched: false, ok: true });
        return json({ ok: true, matched: false });
      }
      const result = await pdFetch(env, "PUT", `/activities/${matchedActivityId}`, { done: 1 });
      await env.OAUTH_KV.put(`ticket_activity:${ticketId}`, String(matchedActivityId));
      await logEvent(env, { ep: "/webhooks/zendesk/solved", ticketId, matchedActivityId, ok: !(result && result.error) });
      return json({ ok: !(result && result.error), matched: true, matchedActivityId });
    }

    // Manually seed a single ticket_activity KV mapping. Used for spot-fixing/testing rather
    // than waiting on the full historical scan below.
    if (path === "/__admin/map-ticket-activity" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const ticketId = url.searchParams.get("ticket_id") || "";
      const activityId = url.searchParams.get("activity_id") || "";
      if (!ticketId || !activityId) return json({ error: "missing ticket_id or activity_id" }, 400);
      await env.OAUTH_KV.put(`ticket_activity:${ticketId}`, activityId);
      return json({ ok: true, ticketId, activityId });
    }

    // One-time reassignment: for every known ticket_activity KV mapping, look up the Zendesk
    // ticket's current assignee, match to a Pipedrive user by email, and set that user as the
    // activity's owner. Chunked via ?offset=N&count=M (default 20) to stay under time limits;
    // response includes totalKeys so callers know when they've covered everything. Safe to re-run.
    if (path === "/__admin/reassign-ticket-activities" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const offset = Number(url.searchParams.get("offset") || "0");
      const count = Number(url.searchParams.get("count") || "20");
      const listRes = await env.OAUTH_KV.list({ prefix: "ticket_activity:" });
      const allKeys = listRes.keys.map((k) => k.name);
      const slice = allKeys.slice(offset, offset + count);
      let processed = 0, reassigned = 0, skipped = 0;
      const errors: any[] = [];
      for (const key of slice) {
        processed++;
        const ticketId = key.replace("ticket_activity:", "");
        const activityId = await env.OAUTH_KV.get(key);
        if (!activityId) { skipped++; continue; }
        try {
          const ticketRes = await zendeskFetch(env, "GET", `/api/v2/tickets/${ticketId}.json`);
          const assigneeId = ticketRes?.ticket?.assignee_id;
          if (!assigneeId) { skipped++; continue; }
          const userRes = await zendeskFetch(env, "GET", `/api/v2/users/${assigneeId}.json`);
          const assigneeEmail = userRes?.user?.email;
          if (!assigneeEmail) { skipped++; continue; }
          const pdUser = await findPipedriveUserByEmail(env, String(assigneeEmail));
          if (!pdUser) { skipped++; continue; }
          const updateRes = await pdFetch(env, "PUT", `/activities/${activityId}`, { user_id: pdUser.id });
          if (updateRes && updateRes.error) { errors.push({ ticketId, activityId, error: updateRes }); continue; }
          reassigned++;
        } catch (e: any) {
          errors.push({ ticketId, activityId, error: e?.message || String(e) });
        }
      }
      return json({ ok: true, totalKeys: allKeys.length, offset, count, processed, reassigned, skipped, errors: errors.slice(0, 10) });
    }

    // One-time backfill: paginate Pipedrive activities and populate the ticket_activity:<id>
    // KV mapping for every one whose subject carries the "Zendesk ticket #<id>:" marker. Needed
    // because activities created before this mapping existed (e.g. the historical backfill) have
    // no KV entry, and Pipedrive's search APIs can't reliably find them by text at scale.
    // Chunked to stay well under request time limits: pass ?start=N to resume; response includes
    // nextStart (call again with that value) or done:true when finished. Safe to re-run (idempotent).
    if (path === "/__admin/backfill-ticket-activity-kv" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const startParam = Number(url.searchParams.get("start") || "0");
      const pagesPerCall = 1; // 500 activities per invocation, comfortably under time limits
      let scanned = 0, mapped = 0, pages = 0;
      let start = startParam;
      let reachedEnd = false;
      for (; pages < pagesPerCall; pages++, start += 500) {
        const res = await pdFetch(env, "GET", `/activities?${new URLSearchParams({ limit: "500", start: String(start), sort: "add_time DESC" })}`);
        const items = Array.isArray(res?.data) ? res.data : [];
        scanned += items.length;
        for (const act of items) {
          const m = typeof act?.subject === "string" ? act.subject.match(/Zendesk ticket #(\d+):/) : null;
          if (m) { await env.OAUTH_KV.put(`ticket_activity:${m[1]}`, String(act.id)); mapped++; }
        }
        if (items.length < 500) { reachedEnd = true; break; }
      }
      return json({ ok: true, scanned, mapped, startedAt: startParam, nextStart: reachedEnd ? null : start, done: reachedEnd });
    }

    // One-time setup helper: registers the Pipedrive webhook subscription (activity updated)
    // pointing at /webhooks/pipedrive/activity. Safe to call more than once (Pipedrive just
    // creates another subscription); intended to be run once after deploy, not on a schedule.
    if (path === "/__admin/setup-pipedrive-webhook" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET || secret !== env.PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const subscriptionUrl = `${url.origin}/webhooks/pipedrive/activity?secret=${encodeURIComponent(env.PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET)}`;
      const result = await pdFetch(env, "POST", "/webhooks", {
        subscription_url: subscriptionUrl,
        event_action: "change",
        event_object: "activity",
      });
      return json({ ok: !(result && result.error), result });
    }

    // Reverse sync: Pipedrive activity marked done -> mark the linked Zendesk ticket solved.
    // Activities created by /webhooks/zendesk have subject "Zendesk ticket #<id>: <title>";
    // we parse the ticket id back out of that rather than needing a separate mapping store.
    if (path === "/webhooks/pipedrive/activity" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET || secret !== env.PIPEDRIVE_ACTIVITY_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      let payload: any = {};
      try { payload = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
      const current = payload.current || payload.data || {};
      const isDone = current.done === true || current.done === 1 || current.done === "1";
      const subject: string = current.subject || "";
      const m = subject.match(/Zendesk ticket #(\d+):/);
      if (!isDone || !m) {
        await logEvent(env, { ep: "/webhooks/pipedrive/activity", activityId: current.id, skipped: true, ok: true });
        return json({ ok: true, skipped: true });
      }
      const ticketId = m[1];
      const result = await zendeskFetch(env, "PUT", `/api/v2/tickets/${ticketId}.json`, { ticket: { status: "solved" } });
      await logEvent(env, { ep: "/webhooks/pipedrive/activity", activityId: current.id, ticketId, ok: !(result && result.error) });
      return json({ ok: !(result && result.error), ticketId });
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
