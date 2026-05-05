import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  PIPEDRIVE_MCP: DurableObjectNamespace<PipedriveMCPContainer>;
  PIPEDRIVE_API_TOKEN: string;
  PIPEDRIVE_COMPANY_DOMAIN: string;
}

export class PipedriveMCPContainer extends Container<Env> {
  // The Pipedrive MCP server listens on this port inside the container
  defaultPort = 8152;

  // Sleep the container after 5 minutes of inactivity to save costs.
  // First request after sleep incurs ~1-3s cold start.
  sleepAfter = "5m";

  // Pass secrets and runtime config from Worker bindings into the container's env.
  // PIPEDRIVE_API_TOKEN and PIPEDRIVE_COMPANY_DOMAIN are stored as Worker secrets
  // (set via `wrangler secret put` or the Cloudflare dashboard).
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Single-instance container (one MCP server for the whole org).
    // For multi-tenant or per-user isolation, swap "singleton" for a request-derived id.
    const container = getContainer(env.PIPEDRIVE_MCP, "singleton");
    return container.fetch(request);
  },
} satisfies ExportedHandler<Env>;

