import { describe, expect, it } from "@effect/vitest";
import {
  buildGraphqlCredential,
  graphqlDraftFromCredentialType,
  normalizeGraphqlEndpoint,
  requiresGraphqlPrivateNetworkOptIn,
  safeGraphqlSourceDetails,
} from "./graphql-source-state";

describe("GraphQL source state", () => {
  it("preserves secret bytes while trimming public credential fields", () => {
    expect(
      buildGraphqlCredential({
        type: "api_key_header",
        headerName: " X-Service-Key ",
        username: "",
        secret: " exact secret ",
      }),
    ).toEqual({ type: "api_key_header", name: "X-Service-Key", value: " exact secret " });
    expect(
      buildGraphqlCredential({
        type: "basic",
        headerName: "",
        username: " operator ",
        secret: " exact password ",
      }),
    ).toEqual({ type: "basic", username: "operator", password: " exact password " });
  });

  it("requires complete credentials and normalizes stored OAuth metadata", () => {
    expect(
      buildGraphqlCredential({
        type: "bearer",
        headerName: "",
        username: "",
        secret: " ",
      }),
    ).toBeUndefined();
    expect(graphqlDraftFromCredentialType("manual_oauth_access_token").type).toBe(
      "oauth_access_token",
    );
  });

  it("detects obvious private endpoints", () => {
    expect(requiresGraphqlPrivateNetworkOptIn("http://127.10.0.1/graphql")).toBe(true);
    expect(requiresGraphqlPrivateNetworkOptIn("http://192.168.2.4/graphql")).toBe(true);
    expect(requiresGraphqlPrivateNetworkOptIn("http://[::ffff:7f00:1]/graphql")).toBe(true);
    expect(requiresGraphqlPrivateNetworkOptIn("https://api.example.test/graphql")).toBe(false);
  });

  it("never exposes endpoint credentials, query parameters, or fragments", () => {
    expect(
      safeGraphqlSourceDetails({
        endpoint: "https://user:pass@api.example.test/graphql?token=secret#private",
        allowPrivateNetwork: false,
      }),
    ).toEqual({ endpoint: "https://api.example.test", allowPrivateNetwork: false });
    expect(
      safeGraphqlSourceDetails({
        endpoint: "https://api.example.test/graphql/path-secret",
        allowPrivateNetwork: false,
      }),
    ).toEqual({ endpoint: "https://api.example.test", allowPrivateNetwork: false });
    expect(normalizeGraphqlEndpoint("https://api.example.test/graphql")).toBe(
      "https://api.example.test/graphql",
    );
    expect(normalizeGraphqlEndpoint("https://api.example.test/graphql?token=secret")).toBeNull();
    expect(normalizeGraphqlEndpoint("https://user:pass@api.example.test/graphql")).toBeNull();
    expect(normalizeGraphqlEndpoint("https://api.example.test/graphql#secret")).toBeNull();
    expect(normalizeGraphqlEndpoint("http://api.example.test/graphql")).toBeNull();
    expect(normalizeGraphqlEndpoint("http://127.0.0.1:4000/graphql")).toBe(
      "http://127.0.0.1:4000/graphql",
    );
  });
});
