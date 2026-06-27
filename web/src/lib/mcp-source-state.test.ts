import { describe, expect, it } from "@effect/vitest";
import {
  MCP_TOKEN_PLACEHOLDER,
  buildMcpHttpCredential,
  downstreamMcpSnippet,
  mcpHttpFingerprint,
  redactedEndpointLabel,
  reconcileTemplateSelection,
  requiresPrivateNetworkOptIn,
  safeMcpSourceDetails,
  templateDescriptorFingerprint,
  templateSecretFields,
  validateTemplateCatalog,
  validateTemplateDraft,
  type McpTemplateField,
} from "./mcp-source-state";

const templateFields = [
  {
    key: "access_token",
    label: "Access token",
    description: "Token issued by the local service.",
    required: true,
    secret: true,
  },
  {
    key: "workspace",
    label: "Workspace",
    description: "Optional workspace name.",
    required: false,
    secret: false,
  },
] as const satisfies readonly McpTemplateField[];

describe("MCP source state", () => {
  it("requires explicit opt-in for obvious local and private endpoints", () => {
    expect(requiresPrivateNetworkOptIn("http://localhost:7331/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("http://10.200.1.8/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("http://127.42.0.1/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("https://192.168.1.8/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("https://172.31.4.2/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("http://[fe9f::1]/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("http://[::ffff:10.200.1.8]/mcp")).toBe(true);
    expect(requiresPrivateNetworkOptIn("https://api.example.com/mcp")).toBe(false);
    expect(requiresPrivateNetworkOptIn("not a URL")).toBe(false);
  });

  it("includes the private-network choice in preview identity", () => {
    expect(mcpHttpFingerprint(" https://example.com/mcp ", false)).toBe(
      "public:https://example.com/mcp",
    );
    expect(mcpHttpFingerprint("https://example.com/mcp", true)).toBe(
      "private:https://example.com/mcp",
    );
  });

  it("removes query credentials and fragments from endpoint labels", () => {
    expect(redactedEndpointLabel("https://example.com/mcp?token=secret#debug")).toBe(
      "https://example.com/mcp",
    );
    expect(redactedEndpointLabel("file:///tmp/server")).toBeNull();
  });

  it("accepts only template-approved fields and enforces required values", () => {
    expect(
      validateTemplateDraft(templateFields, { access_token: " secret ", workspace: "" }),
    ).toEqual({ access_token: " secret " });
    expect(validateTemplateDraft(templateFields, { access_token: "" })).toBeNull();
    expect(
      validateTemplateDraft(templateFields, { access_token: "secret", raw_command: "rm -rf" }),
    ).toBeNull();
  });

  it("builds supported HTTP auth without trimming secret bytes", () => {
    expect(
      buildMcpHttpCredential({ type: "none", headerName: "", username: "", secret: "" }),
    ).toEqual({
      credential: null,
    });
    expect(
      buildMcpHttpCredential({
        type: "bearer",
        headerName: "",
        username: "",
        secret: " exact token ",
      }),
    ).toEqual({ credential: { type: "bearer", token: " exact token " } });
    expect(
      buildMcpHttpCredential({
        type: "api_key_header",
        headerName: " X-Service-Key ",
        username: "",
        secret: " exact key ",
      }),
    ).toEqual({
      credential: { type: "api_key_header", name: "X-Service-Key", value: " exact key " },
    });
    expect(
      buildMcpHttpCredential({
        type: "api_key_header",
        headerName: "",
        username: "",
        secret: "key",
      }),
    ).toBeNull();
    expect(
      buildMcpHttpCredential({
        type: "basic",
        headerName: "",
        username: " admin ",
        secret: " exact password ",
      }),
    ).toEqual({
      credential: { type: "basic", username: "admin", password: " exact password " },
    });
    expect(
      buildMcpHttpCredential({
        type: "oauth_access_token",
        headerName: "",
        username: "",
        secret: " exact oauth token ",
      }),
    ).toEqual({
      credential: { type: "oauth_access_token", access_token: " exact oauth token " },
    });
  });

  it("rejects ambiguous template catalogs and preserves only valid selections", () => {
    expect(
      validateTemplateCatalog([
        { name: "github", secretFields: ["TOKEN"] },
        { name: "github", secretFields: ["OTHER"] },
      ]),
    ).toBeNull();
    expect(
      validateTemplateCatalog([{ name: "github", secretFields: ["TOKEN", "TOKEN"] }]),
    ).toBeNull();
    const templates = [
      { name: "github", secretFields: ["TOKEN"] },
      { name: "linear", secretFields: ["API_KEY"] },
    ];
    expect(reconcileTemplateSelection("linear", templates)).toBe("linear");
    expect(reconcileTemplateSelection("missing", templates)).toBe("github");
    expect(reconcileTemplateSelection(null, [])).toBeNull();
    expect(templateSecretFields(templates[0]!)).toEqual([
      {
        key: "TOKEN",
        label: "TOKEN",
        description: "Secret required by the github template.",
        required: true,
        secret: true,
      },
    ]);
    expect(templateDescriptorFingerprint(templates[0])).toBe('github:["TOKEN"]');
    expect(templateDescriptorFingerprint(null)).toBeNull();
  });

  it("whitelists card metadata without returning sessions, commands, stderr, env, or secrets", () => {
    const details = safeMcpSourceDetails("mcp_http", {
      endpoint: "https://example.com/mcp?api_key=secret",
      negotiatedProtocolVersion: "2025-06-18",
      sessionId: "private-session",
      command: "node",
      stderr: "private output",
      env: { TOKEN: "secret" },
    });

    expect(details).toEqual({
      endpointLabel: "https://example.com/mcp",
      templateName: null,
      negotiatedProtocolVersion: "2025-06-18",
      allowPrivateNetwork: false,
    });
    expect(JSON.stringify(details)).not.toContain("secret");
    expect(JSON.stringify(details)).not.toContain("private-session");
    expect(JSON.stringify(details)).not.toContain("node");
  });

  it("uses a placeholder token in downstream client configuration", () => {
    const snippet = downstreamMcpSnippet("https://executor.example.test/admin");
    expect(snippet).toContain("https://executor.example.test/mcp");
    expect(snippet).toContain(MCP_TOKEN_PLACEHOLDER);
    expect(snippet).not.toContain("sk_live");
  });
});
