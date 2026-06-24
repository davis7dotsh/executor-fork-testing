import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { Schema } from "effect";
import McpCredentialEditor from "./McpCredentialEditor.svelte";
import type { Source } from "./api";

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));

function source(kind: "mcp_http" | "mcp_stdio"): Source {
  return {
    id: `${kind}-source`,
    kind,
    slug: kind,
    displayName: kind === "mcp_http" ? "Remote MCP" : "Local MCP",
    description: null,
    configuration:
      kind === "mcp_http"
        ? { endpoint: "https://mcp.example.test/mcp", allowPrivateNetwork: false }
        : { templateName: "github" },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 3,
    tombstonedToolCount: 0,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("MCP credential editor", () => {
  it("replaces HTTP API-key auth with the viewed CAS revision", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        if (init?.method !== "PUT") {
          return Response.json({ revision: 4, configuredSchemes: [] });
        }
        bodies.push(decodeJson(String(init.body)));
        return Response.json({
          revision: 5,
          configuredSchemes: [{ name: "authorization", credentialType: "api_key_header" }],
        });
      }),
    );
    render(McpCredentialEditor, { source: source("mcp_http") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const method = await screen.findByLabelText<HTMLSelectElement>("Method");
    await fireEvent.change(method, { target: { value: "api_key_header" } });
    await fireEvent.input(screen.getByLabelText("Header name"), {
      target: { value: "X-Service-Key" },
    });
    await fireEvent.input(screen.getByLabelText("Header value"), {
      target: { value: " exact key " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(bodies).toEqual([
      {
        expectedRevision: 4,
        credential: {
          credential: {
            type: "api_key_header",
            name: "X-Service-Key",
            value: " exact key ",
          },
        },
      },
    ]);
    expect(document.body.textContent).not.toContain("exact key");
    expect(document.activeElement).toBe(
      document.getElementById("mcp-credential-status-mcp_http-source"),
    );
  });

  it("uses only template-approved stdio fields and preserves secret bytes", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        if (String(input).endsWith("/credentials") && init?.method !== "PUT") {
          return Response.json({
            revision: 9,
            configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
          });
        }
        if (String(input) === "/api/v1/mcp/stdio/templates") {
          return Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] });
        }
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          revision: 10,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        });
      }),
    );
    render(McpCredentialEditor, { source: source("mcp_stdio") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const secret = await screen.findByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(secret, { target: { value: " exact token " } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(bodies).toEqual([
      {
        expectedRevision: 9,
        credential: { secretValues: { TOKEN: " exact token " } },
      },
    ]);
    expect(document.body.textContent).not.toContain("exact token");
  });

  it("clears secrets and focuses a CAS conflict for review", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          revision: 4,
          configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json(
          {
            error: {
              code: "revision_conflict",
              message: "Credentials changed elsewhere.",
              requestId: "request-conflict",
            },
          },
          { status: 409 },
        ),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpCredentialEditor, { source: source("mcp_http") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(token, { target: { value: "clear-after-conflict" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(screen.queryByLabelText("Bearer token")).toBeNull();
    expect(document.body.textContent).not.toContain("clear-after-conflict");
    expect(document.activeElement).toBe(
      document.getElementById("mcp-credential-error-mcp_http-source"),
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
  });

  it("does not reuse stdio fields when a later template lookup is invalid", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          revision: 2,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      )
      .mockResolvedValueOnce(
        Response.json({
          revision: 3,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "different", secretFields: ["OTHER"] }] }),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpCredentialEditor, { source: source("mcp_stdio") });

    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await screen.findByLabelText("TOKEN");
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(screen.queryByLabelText("TOKEN")).toBeNull();
    expect(screen.queryByLabelText("OTHER")).toBeNull();
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
  });
});
