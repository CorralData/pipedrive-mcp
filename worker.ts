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
  RESEND_API_KEY: string;
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
// Org/deal routing for new Zendesk tickets
// ============================================================================
// Pipelines used for support-ticket routing (both, per decision: a deal can only live in one
// pipeline at a time, and orgs with open deals in both are rare - when it happens, Onboarding
// wins since it represents the more time-sensitive/active relationship).
const ACCOUNT_GROWTH_PIPELINE_ID = 4;
const ONBOARDING_PIPELINE_ID = 10;

// Free/consumer email providers are excluded from domain-based org matching - many unrelated
// people share these domains, so matching on them would misroute tickets to a random org.
const CONSUMER_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "aol.com",
  "protonmail.com", "live.com", "msn.com", "me.com", "comcast.net", "yahoo.co.uk",
]);

function normalizeCompanyText(s: string): string {
  return String(s || "")
    .toLowerCase()
    .replace(/\b(llc|inc|inc\.|corp|corporation|group|co|ltd|company|copy)\b/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function lcsLength(a: string, b: string): number {
  const dp = new Array(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    let prev = 0;
    for (let j = 1; j <= b.length; j++) {
      const temp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev + 1 : Math.max(dp[j], dp[j - 1]);
      prev = temp;
    }
  }
  return dp[b.length];
}

// Approximates difflib.SequenceMatcher ratio (2*matches/total length), same formula used in the
// one-time historical deal-backfill, plus the same +0.9 substring-containment boost/threshold 0.75.
function similarityRatio(a: string, b: string): number {
  if (!a && !b) return 1;
  if (!a || !b) return 0;
  let ratio = (2 * lcsLength(a, b)) / (a.length + b.length);
  if (a.includes(b) || b.includes(a)) ratio = Math.max(ratio, 0.9);
  return ratio;
}

function fuzzyBestMatch(subject: string, candidates: { id: number; title: string }[]): number | null {
  const normSubject = normalizeCompanyText(subject);
  let best: { id: number; score: number } | null = null;
  for (const c of candidates) {
    const score = similarityRatio(normSubject, normalizeCompanyText(c.title));
    if (!best || score > best.score) best = { id: c.id, score };
  }
  return best && best.score >= 0.75 ? best.id : null;
}

// Given a resolved org, pick which specific open deal (if any) a new ticket activity should
// attach to, scoped to Account Growth + Onboarding only. Prefers Onboarding when the org has an
// open deal in both. When a pipeline has 2+ open deals, the standing rule (per Alex) is: default
// to the OLDEST deal for that org (by add_time) - that's the usual pattern. Fuzzy title-matching is
// kept only as a secondary signal: if it finds a strong (>=0.75) match to a *different* deal than the
// oldest one, that more specific match wins (e.g. a ticket explicitly about a named add-on deal),
// otherwise oldest wins.
async function pickDealForOrg(env: Env, orgId: number, ticketSubject: string): Promise<number | null> {
  const res = await pdFetch(env, "GET", `/organizations/${orgId}/deals?${new URLSearchParams({ status: "open", limit: "100" })}`);
  const deals: any[] = Array.isArray(res?.data) ? res.data : [];
  const onboarding = deals.filter((d) => d.pipeline_id === ONBOARDING_PIPELINE_ID);
  const accountGrowth = deals.filter((d) => d.pipeline_id === ACCOUNT_GROWTH_PIPELINE_ID);
  const pool = onboarding.length > 0 ? onboarding : accountGrowth;
  if (pool.length === 0) return null;
  if (pool.length === 1) return pool[0].id;
  const oldest = [...pool].sort((a, b) => new Date(a.add_time).getTime() - new Date(b.add_time).getTime())[0];
  const fuzzyId = fuzzyBestMatch(ticketSubject, pool.map((d) => ({ id: d.id, title: d.title })));
  return fuzzyId && fuzzyId !== oldest.id ? fuzzyId : oldest.id;
}

// Domain -> org_id override map, stored in KV as a flat JSON object (see
// /__admin/set-domain-override). Exists because Pipedrive's /organizations/search endpoint does
// NOT index the organization "website" field (its `fields` param only supports address/custom_fields,
// and search-result items don't even include website) - so there's no way to search Organizations
// directly by domain via the API. This override map is the practical substitute: a small,
// explicitly-curated domain->org table that's checked before falling back to Person-email search.
async function getDomainOverrides(env: Env): Promise<Record<string, number>> {
  const raw = await env.OAUTH_KV.get("domain_org_overrides");
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

// Many of our own ticket subjects follow a "CompanyName // ..." or "CompanyName / ..." convention
// (widget support requests, internally-authored tickets, and system-generated comment
// notifications all do this). This is a last-resort fallback for cases where the requester's
// email is missing, internal (e.g. a CorralData comment-relay address), or doesn't resolve to any
// org - the company name is often sitting right in the subject even when the email is useless.
function extractSubjectOrgHint(subject: string): string | null {
  const cleaned = subject.replace(/^Zendesk ticket #\d+:\s*/, "");
  const m = cleaned.match(/^([^/]{3,60}?)\s*\/\/?\s/);
  return m ? m[1].trim() : null;
}

async function findOrgBySubjectHint(env: Env, hint: string): Promise<number | null> {
  const res = await pdFetch(env, "GET", `/organizations/search?${new URLSearchParams({ term: hint, limit: "10" })}`);
  const items = res?.data?.items || [];
  const candidates = items.map((it: any) => ({ id: it.item.id, title: it.item.name }));
  return fuzzyBestMatch(hint, candidates);
}

// Wraps findOrgForRequester with the subject-hint fallback: only tried when the email-based chain
// came up empty, so it never overrides a confident email/domain match.
async function findOrgForRequesterWithHint(env: Env, email: string | null, subject: string): Promise<{ orgId: number | null; personId: number | null; reason: string }> {
  let routing = email
    ? await findOrgForRequester(env, email)
    : { orgId: null, personId: null, reason: "no_requester_email" };
  if (!routing.orgId) {
    const hint = extractSubjectOrgHint(subject);
    if (hint) {
      const hintOrgId = await findOrgBySubjectHint(env, hint);
      if (hintOrgId) return { orgId: hintOrgId, personId: routing.personId, reason: "subject_name_fallback_match" };
    }
  }
  return routing;
}

// Best-effort display name for a brand-new Person record when the Zendesk requester name is
// missing/blank - title-cases the email's local part (e.g. "jane.doe" -> "Jane Doe").
function bestEffortNameFromEmail(email: string): string {
  const local = email.split("@")[0] || email;
  const words = local.replace(/[._+-]+/g, " ").split(" ").filter(Boolean);
  return words.length ? words.map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ") : email;
}

// Self-heals an existing Person record that's missing (or disagrees with) its org link, by
// writing the resolved org_id back to Pipedrive. Only called with a confident single-org signal
// (domain_org_overrides hit or an unambiguous domain_fallback_single_org match) - never for
// ambiguous/tiebreak cases. Swallows failures (falls back to the un-healed reason) so a Pipedrive
// write hiccup never blocks routing.
async function healPersonOrgLink(env: Env, personId: number, orgId: number): Promise<boolean> {
  const result = await pdFetch(env, "PUT", `/persons/${personId}`, { org_id: orgId });
  return !(result && result.error);
}

// Normalizes a string to lowercase alphanumeric-only - stricter than normalizeCompanyText (which
// keeps spaces and strips legal-entity suffixes), since here we're comparing an org name directly
// against a domain-derived token that already has no separators at all.
function normalizeToAlnum(s: string): string {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

// Derives a human-readable search term and a fully-collapsed comparison token from an email
// domain, e.g. "moon-juice-inc.com" -> term "moon juice inc", token "moonjuiceinc". Drops the TLD
// (last dot-segment) and turns any remaining separators into spaces for the search term.
function domainToNameGuess(domain: string): { term: string; token: string } {
  const withoutTld = domain.split(".").slice(0, -1).join(" ");
  const term = withoutTld.replace(/[^a-zA-Z0-9]+/g, " ").trim();
  return { term, token: normalizeToAlnum(term) };
}

// Last-resort fallback inside findOrgForRequester for when there's no domain_org_overrides entry
// and no Person (existing or domain-matched) points to any org at all: guesses that the domain
// obviously names an existing Pipedrive org (e.g. "moonjuice.com" -> org "Moon Juice") and searches
// Organizations for it (same /organizations/search endpoint as the search_organizations tool).
// Only returns a match when confident - either the normalized org name equals the normalized
// domain token, or exactly one candidate has a substring-containment match and no other candidate
// is equally close. Ambiguous or weak results return null so the caller still falls through to the
// real alert (see no_org_found_for_domain below).
async function findOrgByFuzzyDomainName(env: Env, domain: string): Promise<number | null> {
  const { term, token } = domainToNameGuess(domain);
  if (token.length < 3) return null;
  const res = await pdFetch(env, "GET", `/organizations/search?${new URLSearchParams({ term, limit: "10" })}`);
  const items = res?.data?.items || [];
  const candidates = items
    .map((it: any) => ({ id: it.item.id, norm: normalizeToAlnum(it.item.name) }))
    .filter((c: any) => c.norm);
  const exact = candidates.filter((c: any) => c.norm === token);
  if (exact.length === 1) return exact[0].id;
  if (exact.length > 1) return null; // multiple orgs share the identical normalized name - ambiguous
  const contained = candidates.filter((c: any) => c.norm.includes(token) || token.includes(c.norm));
  return contained.length === 1 ? contained[0].id : null;
}

// Persists a new domain_org_overrides entry (read-modify-write, same pattern as
// /__admin/domain-overrides) after a confident findOrgByFuzzyDomainName match, so future tickets
// from this domain skip the fuzzy search entirely and hit the curated override instead.
async function persistDomainOverride(env: Env, domain: string, orgId: number): Promise<void> {
  const overrides = await getDomainOverrides(env);
  if (overrides[domain] !== orgId) {
    overrides[domain] = orgId;
    await env.OAUTH_KV.put("domain_org_overrides", JSON.stringify(overrides));
  }
}

// Full org-matching chain for a new ticket's requester: exact-email Person match first (as
// before), then a curated domain-override lookup (no Person required - see getDomainOverrides),
// then a Person-based domain fallback for everything else, with an open-deal tiebreak (scoped to
// Account Growth/Onboarding) when a domain maps to more than one org (duplicate org records).
// Returns null org/deal when nothing can be confidently resolved rather than guessing - callers
// should flag those for review.
// Self-healing: when the matched Person has no org_id (or one that disagrees with a confident
// domain_org_overrides hit), this writes the resolved org_id back onto the Person via
// healPersonOrgLink instead of just alerting Alex to link it by hand - reason
// "auto_healed_person_org_link" in that case, still routes/logs as a normal success (no alert).
async function findOrgForRequester(env: Env, email: string): Promise<{ orgId: number | null; personId: number | null; reason: string }> {
  const target = email.trim().toLowerCase();
  const person = await findPersonByExactEmail(env, target);
  const personId = person ? person.id : null;
  const personOrgId = person ? ((person.organization && person.organization.id) || person.org_id || null) : null;
  const domain = target.split("@")[1];
  if (!domain || CONSUMER_EMAIL_DOMAINS.has(domain)) {
    if (personOrgId) return { orgId: personOrgId, personId, reason: "exact_person_match" };
    return { orgId: null, personId, reason: "no_org_generic_or_missing_domain" };
  }
  const overrides = await getDomainOverrides(env);
  const overrideOrgId = overrides[domain] || null;
  if (personOrgId) {
    // Already linked. Cheap self-heal check: a curated override disagreeing with what's on the
    // Person record means the link is stale/wrong - fix it. Otherwise trust the existing link.
    if (overrideOrgId && overrideOrgId !== personOrgId && personId && (await healPersonOrgLink(env, personId, overrideOrgId))) {
      return { orgId: overrideOrgId, personId, reason: "auto_healed_person_org_link" };
    }
    return { orgId: personOrgId, personId, reason: "exact_person_match" };
  }
  // Person exists but has no org_id at all, or there's no Person yet - try domain-based signals.
  if (overrideOrgId) {
    if (personId && (await healPersonOrgLink(env, personId, overrideOrgId))) {
      return { orgId: overrideOrgId, personId, reason: "auto_healed_person_org_link" };
    }
    return { orgId: overrideOrgId, personId, reason: "domain_override_match" };
  }
  const searchRes = await pdFetch(env, "GET", `/persons/search?${new URLSearchParams({ term: `@${domain}`, fields: "email", limit: "50" })}`);
  const items = searchRes?.data?.items || [];
  const orgIds = new Set<number>();
  for (const it of items) {
    const p = it.item;
    const oid = (p && p.organization && p.organization.id) || (p && p.org_id);
    if (oid) orgIds.add(oid);
  }
  if (orgIds.size === 0) {
    // No Person at all resolves this domain to an org - try a fuzzy org-name-to-domain guess
    // (see findOrgByFuzzyDomainName) before giving up and alerting Alex.
    const fuzzyOrgId = await findOrgByFuzzyDomainName(env, domain);
    if (fuzzyOrgId) {
      await persistDomainOverride(env, domain, fuzzyOrgId);
      return { orgId: fuzzyOrgId, personId, reason: "fuzzy_org_name_domain_match" };
    }
    return { orgId: null, personId, reason: "no_org_found_for_domain" };
  }
  if (orgIds.size === 1) {
    const singleOrgId = [...orgIds][0];
    if (personId && (await healPersonOrgLink(env, personId, singleOrgId))) {
      return { orgId: singleOrgId, personId, reason: "auto_healed_person_org_link" };
    }
    return { orgId: singleOrgId, personId, reason: "domain_fallback_single_org" };
  }
  // Multiple distinct orgs share this domain (duplicate org records) - tiebreak on which one has
  // an open deal in Account Growth or Onboarding. If more than one qualifies, stay ambiguous.
  let candidateOrgId: number | null = null;
  for (const oid of orgIds) {
    const dealsRes = await pdFetch(env, "GET", `/organizations/${oid}/deals?${new URLSearchParams({ status: "open", limit: "50" })}`);
    const deals: any[] = Array.isArray(dealsRes?.data) ? dealsRes.data : [];
    const scoped = deals.filter((d) => d.pipeline_id === ACCOUNT_GROWTH_PIPELINE_ID || d.pipeline_id === ONBOARDING_PIPELINE_ID);
    if (scoped.length > 0) {
      if (candidateOrgId !== null) return { orgId: null, personId, reason: "ambiguous_multiple_orgs_with_deals" };
      candidateOrgId = oid;
    }
  }
  if (candidateOrgId !== null) return { orgId: candidateOrgId, personId, reason: "domain_fallback_tiebreak_open_deal" };
  return { orgId: null, personId, reason: "ambiguous_multiple_orgs_no_deals" };
}

// Creates a new Pipedrive Person for a domain-fallback/override match that has no existing
// Person record for this exact email, linked directly to the resolved org_id. Mirrors the manual
// step Alex was doing by hand for every new domain-matched contact (weramp.com, Sand Cloud,
// Chamberlain, Aviva Aesthetics, etc.) - name prefers the Zendesk requester's display name, else
// a best-effort guess from the email. Only called for confident single-org reasons (see caller in
// /webhooks/zendesk); failures return null and the ticket still routes to the org, just without a
// person_id (same as today's behavior).
async function createPersonForDomainMatch(env: Env, email: string, requesterName: string | undefined | null, orgId: number): Promise<number | null> {
  const name = (requesterName && requesterName.trim()) || bestEffortNameFromEmail(email);
  const result = await pdFetch(env, "POST", "/persons", { name, email: [email], org_id: orgId });
  return result && result.data && result.data.id ? result.data.id : null;
}

// ============================================================================
// Routing-exception alerts (Resend)
// ============================================================================
// Whenever live ticket routing can't confidently resolve an org (see findOrgForRequesterWithHint
// in /webhooks/zendesk below) or the Pipedrive activity create call itself fails, Alex gets emailed
// immediately (not batched) - these are rare enough day-to-day that real-time beats a daily rollup.
async function sendResendEmail(env: Env, opts: { to: string; subject: string; html: string }): Promise<any> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: "CorralData Ops <ops@updates.corraldata.com>",
      to: [opts.to],
      subject: opts.subject,
      html: opts.html,
    }),
  });
  const text = await res.text();
  let data: any;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  if (!res.ok) return { error: true, status: res.status, body: data };
  return data;
}

function formatEtTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-US", {
      timeZone: "America/New_York",
      dateStyle: "medium",
      timeStyle: "short",
    }) + " ET";
  } catch { return iso; }
}

// Sends one immediate email for a single routing exception. Failures are swallowed (logged via
// logEvent by the caller) rather than thrown - a Resend outage should never block ticket sync.
async function sendExceptionAlert(env: Env, item: { ticketId: any; subject?: string; ticketUrl?: string; reason: string }): Promise<any> {
  const ts = formatEtTimestamp(new Date().toISOString());
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:auto;">
      <h2 style="margin-bottom:4px;">Pipedrive routing exception</h2>
      <p style="color:#555;margin-top:0;">A Zendesk ticket couldn't be auto-routed to a Pipedrive org. Fix via a domain override (<code>/__admin/domain-overrides</code>) or org merge - it'll route correctly going forward, no need to re-run anything.</p>
      <table style="border-collapse:collapse;width:100%;font-size:14px;">
        <tr><td style="padding:6px 12px;color:#777;">When</td><td style="padding:6px 12px;">${ts}</td></tr>
        <tr><td style="padding:6px 12px;color:#777;">Ticket</td><td style="padding:6px 12px;">${item.ticketUrl ? `<a href="${item.ticketUrl}">#${item.ticketId}</a>` : `#${item.ticketId}`}</td></tr>
        <tr><td style="padding:6px 12px;color:#777;">Subject</td><td style="padding:6px 12px;">${String(item.subject || "").replace(/</g, "&lt;")}</td></tr>
        <tr><td style="padding:6px 12px;color:#777;">Reason</td><td style="padding:6px 12px;">${item.reason}</td></tr>
      </table>
    </div>`;
  return sendResendEmail(env, {
    to: "alex@corraldata.com",
    subject: `Pipedrive routing exception: ticket #${item.ticketId} needs review`,
    html,
  });
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
  { name: "update_person", description: "Update fields on an existing Pipedrive person, e.g. reassign them to a different organization via org_id. Pass only the fields to change.", inputSchema: { type: "object", properties: { id: { type: "number", description: "Person ID to update. Required." }, name: { type: "string" }, org_id: { type: "number", description: "Reassign this person to a different organization." }, owner_id: { type: "number" } }, required: ["id"], additionalProperties: true } },
  { name: "delete_organization", description: "Permanently delete a Pipedrive organization by ID. This does NOT move its deals/persons/activities elsewhere first - call merge_organizations instead if you want to consolidate a duplicate into a surviving org. This cannot be undone.", inputSchema: { type: "object", properties: { id: { type: "number", description: "Organization ID to delete. Required." } }, required: ["id"] } },
  { name: "merge_organizations", description: "Merge two Pipedrive organizations into one, per Pipedrive's native merge behavior. IMPORTANT direction: the organization identified by 'id' is the one that gets MERGED AWAY (deleted); 'merge_with_id' is the organization that SURVIVES and absorbs all of id's deals, persons, activities, notes, and files. So pass the duplicate/stub org as 'id' and the real/primary org you want to keep as 'merge_with_id'. This cannot be undone - verify direction carefully before calling.", inputSchema: { type: "object", properties: { id: { type: "number", description: "Organization ID that will be merged away (deleted). Required." }, merge_with_id: { type: "number", description: "Organization ID that survives and receives everything from 'id'. Required." } }, required: ["id", "merge_with_id"] } },
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
    case "update_person": { const { id, ...body } = args; return pdFetch(env, "PUT", `/persons/${id}`, body); }
    case "delete_organization": return pdFetch(env, "DELETE", `/organizations/${args.id}`);
    case "merge_organizations": { const { id, merge_with_id } = args; return pdFetch(env, "PUT", `/organizations/${id}/merge`, { merge_with_id }); }
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
    // Forward sync: new Zendesk ticket -> new Pipedrive activity.
    // Org routing: exact-email Person match first, then a domain fallback (findOrgForRequester)
    // that also tiebreaks duplicate org records via open-deal presence in Account
    // Growth/Onboarding. Deal routing: pickDealForOrg attaches a specific open deal when the
    // matched org has exactly one (or a confident fuzzy-title match), preferring Onboarding.
    if (path === "/webhooks/zendesk" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      let payload: any = {};
      try { payload = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }
      const ticketId = payload.ticket_id;
      const excludedRaw = await env.OAUTH_KV.get("excluded_tickets");
      const excludedSet = new Set<string>(excludedRaw ? JSON.parse(excludedRaw) : []);
      if (excludedSet.has(String(ticketId))) {
        await logEvent(env, { ep: "/webhooks/zendesk", ticketId, excluded: true, ok: true });
        return json({ ok: true, excluded: true });
      }
      const subject = payload.subject || "Zendesk ticket";
      const email = payload.requester_email;
      const ticketUrl = payload.ticket_url;
      // Silent noise auto-exclusion (see /__admin/known-noise-senders): unlike excluded_tickets
      // (one ticket ID at a time), this keys off the requester's email so every future ticket from
      // a known automation/notification sender (Customer.io, Fathom, Fireflies, etc.) is skipped
      // without needing Alex to add each new ticket ID by hand. Defaults to empty if unset.
      const noiseRaw = await env.OAUTH_KV.get("known_noise_senders");
      const noiseSet = new Set<string>(
        noiseRaw ? (JSON.parse(noiseRaw) as string[]).map((e) => e.trim().toLowerCase()) : []
      );
      if (email && noiseSet.has(String(email).trim().toLowerCase())) {
        await logEvent(env, { ep: "/webhooks/zendesk", ticketId, noiseSender: true, ok: true });
        return json({ ok: true, noiseSender: true });
      }
      const routing = await findOrgForRequesterWithHint(env, email ? String(email) : null, subject);
      // Auto-create a Person for a domain-fallback/override match that has no existing Person yet
      // (see createPersonForDomainMatch) - only for the confident, non-ambiguous reasons, so this
      // never creates a Person off an uncertain/tiebreak match. Self-healing of an *existing*
      // Person's org_id happens inside findOrgForRequester itself (reason auto_healed_person_org_link).
      if (!routing.personId && routing.orgId && email &&
          (routing.reason === "domain_override_match" || routing.reason === "domain_fallback_single_org" ||
           routing.reason === "fuzzy_org_name_domain_match")) {
        const newPersonId = await createPersonForDomainMatch(env, String(email), payload.requester_name, routing.orgId);
        if (newPersonId) routing.personId = newPersonId;
      }
      let dealId: number | null = null;
      if (routing.orgId) dealId = await pickDealForOrg(env, routing.orgId, subject);
      const assigneeEmail = payload.assignee_email;
      const assigneeUserMatch = assigneeEmail ? await findPipedriveUserByEmail(env, String(assigneeEmail)) : null;
      const noteLines = [`${ticketUrl || ""} - Requester: ${payload.requester_name || ""} <${email || ""}>`];
      if (!routing.orgId) noteLines.push(`[Needs manual org link - routing reason: ${routing.reason}]`);
      const activityBody: any = {
        subject: `Zendesk ticket #${ticketId}: ${subject}`,
        type: "task",
        note: noteLines.join("\n"),
      };
      if (routing.personId) activityBody.person_id = routing.personId;
      if (routing.orgId) activityBody.org_id = routing.orgId;
      if (dealId) activityBody.deal_id = dealId;
      if (assigneeUserMatch) activityBody.user_id = assigneeUserMatch.id;
      const result = await pdFetch(env, "POST", "/activities", activityBody);
      if (result && result.data && result.data.id) {
        await env.OAUTH_KV.put(`ticket_activity:${ticketId}`, String(result.data.id));
      }
      if (!routing.orgId || (result && result.error)) {
        const alertResult = await sendExceptionAlert(env, {
          ticketId,
          subject,
          ticketUrl,
          reason: !routing.orgId ? routing.reason : "pipedrive_activity_create_failed",
        });
        await logEvent(env, { ep: "exception_alert", ticketId, ok: !(alertResult && alertResult.error), alertResult: alertResult?.error ? alertResult : undefined });
      }
      await logEvent(env, { ep: "/webhooks/zendesk", ticketId, orgId: routing.orgId, dealId, reason: routing.reason, ok: !(result && result.error) });
      return json({ ok: !(result && result.error), matchedOrg: !!routing.orgId, matchedDeal: !!dealId, reason: routing.reason });
    }

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

    // Domain -> org_id override table (see getDomainOverrides / findOrgForRequester). GET lists
    // the current map; POST with ?domain=X&org_id=Y adds/updates one entry. This is the practical
    // substitute for organization-domain search, which Pipedrive's API doesn't support.
    if (path === "/__admin/domain-overrides") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      if (request.method === "GET") {
        return json({ ok: true, overrides: await getDomainOverrides(env) });
      }
      if (request.method === "POST") {
        const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();
        const orgId = Number(url.searchParams.get("org_id") || "");
        if (!domain || !orgId) return json({ error: "missing domain or org_id" }, 400);
        const overrides = await getDomainOverrides(env);
        overrides[domain] = orgId;
        await env.OAUTH_KV.put("domain_org_overrides", JSON.stringify(overrides));
        return json({ ok: true, domain, orgId, overrides });
      }
      return new Response("Method not allowed", { status: 405 });
    }

    // Diagnostic: look up a Zendesk ticket's requester (id, name, email) directly. Used for
    // manually investigating routing gaps (e.g. tickets with no requester_email surfaced via the
    // backfill) without needing a separate Zendesk tool.
    if (path === "/__admin/zendesk-ticket-requester" && request.method === "GET") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const ticketId = url.searchParams.get("ticket_id") || "";
      if (!ticketId) return json({ error: "missing ticket_id" }, 400);
      const ticketRes = await zendeskFetch(env, "GET", `/api/v2/tickets/${ticketId}.json`);
      const requesterId = ticketRes?.ticket?.requester_id;
      let requester: any = null;
      if (requesterId) {
        const userRes = await zendeskFetch(env, "GET", `/api/v2/users/${requesterId}.json`);
        requester = userRes?.user
          ? { id: userRes.user.id, name: userRes.user.name, email: userRes.user.email, role: userRes.user.role }
          : { error: userRes };
      }
      return json({ ok: true, ticketId, organization_id: ticketRes?.ticket?.organization_id, assignee_id: ticketRes?.ticket?.assignee_id, requester });
    }

    // Excluded-ticket set (see EXCLUDED_TICKETS check in /webhooks/zendesk and backfill-org-routing):
    // tickets that should never get a Pipedrive activity/org link at all (vendor spam, list-seller
    // emails, etc. that land in the support inbox but aren't real customer requests). GET lists the
    // set; POST with ?ticket_id=X adds one.
    if (path === "/__admin/excluded-tickets") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      if (request.method === "GET") {
        const raw = await env.OAUTH_KV.get("excluded_tickets");
        return json({ ok: true, excluded: raw ? JSON.parse(raw) : [] });
      }
      if (request.method === "POST") {
        const ticketId = url.searchParams.get("ticket_id") || "";
        if (!ticketId) return json({ error: "missing ticket_id" }, 400);
        const raw = await env.OAUTH_KV.get("excluded_tickets");
        const list: string[] = raw ? JSON.parse(raw) : [];
        if (!list.includes(ticketId)) list.push(ticketId);
        await env.OAUTH_KV.put("excluded_tickets", JSON.stringify(list));
        return json({ ok: true, excluded: list });
      }
      return new Response("Method not allowed", { status: 405 });
    }

    // Known-noise-sender set (see noiseSet check in /webhooks/zendesk): exact requester email
    // addresses that should never route or alert, for ANY future ticket - not just one ticket ID
    // (that's what excluded_tickets is for). Meant for automation/notification senders (Customer.io,
    // Fathom, Fireflies, etc.) that show up in the support inbox repeatedly. GET lists the set;
    // POST with ?email=X adds one (stored lowercase/trimmed).
    if (path === "/__admin/known-noise-senders") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      if (request.method === "GET") {
        const raw = await env.OAUTH_KV.get("known_noise_senders");
        return json({ ok: true, noiseSenders: raw ? JSON.parse(raw) : [] });
      }
      if (request.method === "POST") {
        const email = (url.searchParams.get("email") || "").trim().toLowerCase();
        if (!email) return json({ error: "missing email" }, 400);
        const raw = await env.OAUTH_KV.get("known_noise_senders");
        const list: string[] = raw ? JSON.parse(raw) : [];
        if (!list.includes(email)) list.push(email);
        await env.OAUTH_KV.put("known_noise_senders", JSON.stringify(list));
        return json({ ok: true, noiseSenders: list });
      }
      return new Response("Method not allowed", { status: 405 });
    }

    // Manual test of the routing-exception alert path (see sendExceptionAlert above) - fires one
    // real email via Resend without needing a live Zendesk ticket to fail routing first.
    if (path === "/__admin/test-exception-alert" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const result = await sendExceptionAlert(env, {
        ticketId: "TEST",
        subject: "Test exception alert",
        reason: "manual_test",
      });
      return json({ ok: !(result && result.error), result });
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
      const skipReasons: any[] = [];
      for (const key of slice) {
        processed++;
        const ticketId = key.replace("ticket_activity:", "");
        const activityId = await env.OAUTH_KV.get(key);
        if (!activityId) { skipped++; skipReasons.push({ ticketId, reason: "no_activity_id" }); continue; }
        try {
          const ticketRes = await zendeskFetch(env, "GET", `/api/v2/tickets/${ticketId}.json`);
          const assigneeId = ticketRes?.ticket?.assignee_id;
          if (!assigneeId) { skipped++; skipReasons.push({ ticketId, reason: "no_assignee", ticketRes: ticketRes?.error ? ticketRes : undefined }); continue; }
          const userRes = await zendeskFetch(env, "GET", `/api/v2/users/${assigneeId}.json`);
          const assigneeEmail = userRes?.user?.email;
          if (!assigneeEmail) { skipped++; skipReasons.push({ ticketId, reason: "no_assignee_email", userRes: userRes?.error ? userRes : undefined }); continue; }
          const pdUser = await findPipedriveUserByEmail(env, String(assigneeEmail));
          if (!pdUser) { skipped++; skipReasons.push({ ticketId, reason: "no_pd_user_match", assigneeEmail }); continue; }
          const updateRes = await pdFetch(env, "PUT", `/activities/${activityId}`, { user_id: pdUser.id });
          if (updateRes && updateRes.error) { errors.push({ ticketId, activityId, error: updateRes }); continue; }
          reassigned++;
        } catch (e: any) {
          errors.push({ ticketId, activityId, error: e?.message || String(e) });
        }
      }
      return json({ ok: true, totalKeys: allKeys.length, offset, count, processed, reassigned, skipped, skipReasons: skipReasons.slice(0, 20), errors: errors.slice(0, 10) });
    }

    // Retroactive cleanup: for every known ticket_activity KV mapping whose Pipedrive activity
    // currently has NO org_id, re-run the new findOrgForRequester/pickDealForOrg logic (domain
    // fallback + duplicate-org tiebreak, now that duplicate orgs have been merged) against the
    // Zendesk ticket's real requester email, and update the activity if it now resolves. Activities
    // that already have an org_id are left untouched - this only fixes previously-unmatched ones,
    // never overwrites an existing match. Chunked via ?offset=N&count=M (default 15, kept small
    // since each item does several Pipedrive + Zendesk calls). Safe to re-run.
    if (path === "/__admin/backfill-org-routing" && request.method === "POST") {
      const secret = url.searchParams.get("secret") || "";
      if (!env.ZENDESK_WEBHOOK_SECRET || secret !== env.ZENDESK_WEBHOOK_SECRET) {
        return new Response("Unauthorized", { status: 401 });
      }
      const offset = Number(url.searchParams.get("offset") || "0");
      const count = Number(url.searchParams.get("count") || "15");
      const listRes = await env.OAUTH_KV.list({ prefix: "ticket_activity:" });
      const allKeys = listRes.keys.map((k) => k.name);
      const slice = allKeys.slice(offset, offset + count);
      const excludedRaw = await env.OAUTH_KV.get("excluded_tickets");
      const excludedSet = new Set<string>(excludedRaw ? JSON.parse(excludedRaw) : []);
      let processed = 0, alreadyHadOrg = 0, fixed = 0, stillUnresolved = 0, excluded = 0;
      const fixedDetails: any[] = [];
      const unresolvedReasons: any[] = [];
      const errors: any[] = [];
      for (const key of slice) {
        processed++;
        const ticketId = key.replace("ticket_activity:", "");
        if (excludedSet.has(ticketId)) { excluded++; continue; }
        const activityId = await env.OAUTH_KV.get(key);
        if (!activityId) { unresolvedReasons.push({ ticketId, reason: "no_activity_id" }); continue; }
        try {
          const activityRes = await pdFetch(env, "GET", `/activities/${activityId}`);
          const activity = activityRes?.data;
          if (!activity) { errors.push({ ticketId, activityId, error: "activity_fetch_failed" }); continue; }
          if (activity.org_id) { alreadyHadOrg++; continue; }
          const ticketRes = await zendeskFetch(env, "GET", `/api/v2/tickets/${ticketId}.json`);
          const requesterId = ticketRes?.ticket?.requester_id;
          let requesterEmail: string | null = null;
          if (requesterId) {
            const userRes = await zendeskFetch(env, "GET", `/api/v2/users/${requesterId}.json`);
            requesterEmail = userRes?.user?.email || null;
          }
          const routing = await findOrgForRequesterWithHint(env, requesterEmail, activity.subject || "");
          if (!routing.orgId) { stillUnresolved++; unresolvedReasons.push({ ticketId, activityId, reason: routing.reason }); continue; }
          const dealId = await pickDealForOrg(env, routing.orgId, activity.subject || "");
          const updateBody: any = { org_id: routing.orgId };
          if (routing.personId) updateBody.person_id = routing.personId;
          if (dealId) updateBody.deal_id = dealId;
          const updateRes = await pdFetch(env, "PUT", `/activities/${activityId}`, updateBody);
          if (updateRes && updateRes.error) { errors.push({ ticketId, activityId, error: updateRes }); continue; }
          fixed++;
          fixedDetails.push({ ticketId, activityId, orgId: routing.orgId, dealId, reason: routing.reason });
        } catch (e: any) {
          errors.push({ ticketId, activityId, error: e?.message || String(e) });
        }
      }
      return json({ ok: true, totalKeys: allKeys.length, offset, count, processed, alreadyHadOrg, fixed, excluded, stillUnresolved, fixedDetails, unresolvedReasons: unresolvedReasons.slice(0, 20), errors: errors.slice(0, 10) });
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
