export type McpSourceKind = "mcp_http" | "mcp_stdio";

export type McpTemplateField = {
  readonly key: string;
  readonly label: string;
  readonly description: string;
  readonly required: boolean;
  readonly secret: boolean;
};

export type McpTemplateDraft = Readonly<Record<string, string>>;

export type McpHttpAuthDraft = {
  readonly type: "none" | "bearer" | "basic" | "api_key_header" | "oauth_access_token";
  readonly headerName: string;
  readonly username: string;
  readonly secret: string;
};

export type McpTemplateSummary = {
  readonly name: string;
  readonly secretFields: readonly string[];
};

export type SafeMcpSourceDetails = {
  readonly endpointLabel: string | null;
  readonly templateName: string | null;
  readonly negotiatedProtocolVersion: string | null;
  readonly allowPrivateNetwork: boolean;
};

export const MCP_TOKEN_PLACEHOLDER = "<EXECUTOR_API_TOKEN>";

export function mcpHttpFingerprint(endpoint: string, allowPrivateNetwork: boolean) {
  return `${allowPrivateNetwork ? "private" : "public"}:${endpoint.trim()}`;
}

export function requiresPrivateNetworkOptIn(endpoint: string) {
  const url = parseHttpUrl(endpoint);
  if (url === null) return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host === "::1" || isPrivateIpv6(host)) {
    return true;
  }
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) return false;
  return isPrivateIpv4(octets);
}

function isPrivateIpv4(octets: readonly number[]) {
  if (octets[0] === 10 || octets[0] === 127) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  return octets[0] === 192 && octets[1] === 168;
}

export function redactedEndpointLabel(endpoint: string) {
  const url = parseHttpUrl(endpoint);
  if (url === null) return null;
  return `${url.origin}${url.pathname}`;
}

export function validateTemplateDraft(
  fields: readonly McpTemplateField[],
  draft: McpTemplateDraft,
) {
  const allowedKeys = new Set(fields.map((field) => field.key));
  const hasUnknownField = Object.keys(draft).some((key) => !allowedKeys.has(key));
  if (hasUnknownField) return null;

  const values: Record<string, string> = {};
  for (const field of fields) {
    const rawValue = draft[field.key] ?? "";
    if (field.required && rawValue.trim() === "") return null;
    if (rawValue !== "") values[field.key] = field.secret ? rawValue : rawValue.trim();
  }
  return values;
}

export function buildMcpHttpCredential(draft: McpHttpAuthDraft) {
  if (draft.type === "none") return { credential: null } as const;
  if (draft.secret.trim() === "") return null;
  if (draft.type === "bearer") {
    return { credential: { type: "bearer", token: draft.secret } } as const;
  }
  if (draft.type === "basic") {
    const username = draft.username.trim();
    if (username === "") return null;
    return { credential: { type: "basic", username, password: draft.secret } } as const;
  }
  if (draft.type === "oauth_access_token") {
    return {
      credential: { type: "oauth_access_token", access_token: draft.secret },
    } as const;
  }
  const name = draft.headerName.trim();
  if (name === "") return null;
  return { credential: { type: "api_key_header", name, value: draft.secret } } as const;
}

export function validateTemplateCatalog(templates: readonly McpTemplateSummary[]) {
  const names = new Set<string>();
  const validated: McpTemplateSummary[] = [];
  for (const template of templates) {
    if (template.name.trim() === "" || names.has(template.name)) return null;
    names.add(template.name);
    const fields = new Set<string>();
    for (const field of template.secretFields) {
      if (field.trim() === "" || fields.has(field)) return null;
      fields.add(field);
    }
    validated.push({ name: template.name, secretFields: [...template.secretFields] });
  }
  return validated;
}

export function reconcileTemplateSelection(
  selected: string | null,
  templates: readonly McpTemplateSummary[],
) {
  if (selected !== null && templates.some((template) => template.name === selected)) {
    return selected;
  }
  return templates[0]?.name ?? null;
}

export function templateDescriptorFingerprint(template: McpTemplateSummary | null | undefined) {
  return template === null || template === undefined
    ? null
    : `${template.name}:${JSON.stringify(template.secretFields)}`;
}

export function templateSecretFields(template: McpTemplateSummary): readonly McpTemplateField[] {
  return template.secretFields.map((key) => ({
    key,
    label: key,
    description: `Secret required by the ${template.name} template.`,
    required: true,
    secret: true,
  }));
}

export function safeMcpSourceDetails(
  kind: McpSourceKind,
  configuration: Readonly<Record<string, unknown>>,
): SafeMcpSourceDetails {
  return {
    endpointLabel:
      kind === "mcp_http" && typeof configuration.endpoint === "string"
        ? redactedEndpointLabel(configuration.endpoint)
        : null,
    templateName:
      kind === "mcp_stdio" && typeof configuration.templateName === "string"
        ? configuration.templateName
        : null,
    negotiatedProtocolVersion:
      typeof configuration.negotiatedProtocolVersion === "string"
        ? configuration.negotiatedProtocolVersion
        : null,
    allowPrivateNetwork: configuration.allowPrivateNetwork === true,
  };
}

export function downstreamMcpSnippet(origin: string) {
  const endpoint = new URL("/mcp", origin).toString();
  return JSON.stringify(
    {
      mcpServers: {
        executor: {
          type: "http",
          url: endpoint,
          headers: { Authorization: `Bearer ${MCP_TOKEN_PLACEHOLDER}` },
        },
      },
    },
    null,
    2,
  );
}

function parseHttpUrl(value: string) {
  const normalized = value.trim();
  if (!URL.canParse(normalized)) return null;
  const url = new URL(normalized);
  return url.protocol === "http:" || url.protocol === "https:" ? url : null;
}

function isPrivateIpv6(host: string) {
  if (host.startsWith("fc") || host.startsWith("fd")) return true;
  if (host.startsWith("::ffff:")) {
    const groups = host.split(":");
    const high = Number.parseInt(groups.at(-2) ?? "", 16);
    const low = Number.parseInt(groups.at(-1) ?? "", 16);
    if (Number.isInteger(high) && Number.isInteger(low)) {
      return isPrivateIpv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
    }
  }
  const firstGroup = Number.parseInt(host.split(":", 1)[0] ?? "", 16);
  return Number.isInteger(firstGroup) && firstGroup >= 0xfe80 && firstGroup <= 0xfebf;
}
