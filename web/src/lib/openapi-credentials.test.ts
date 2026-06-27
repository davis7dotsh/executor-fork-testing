import { describe, expect, it } from "@effect/vitest";
import {
  buildCredentialMap,
  duplicateCredentialNames,
  type CredentialDraft,
} from "./openapi-credentials";

function draft(
  name: string,
  credentialType: CredentialDraft["credentialType"],
  value: string,
  username = "",
): CredentialDraft {
  return { key: name, name, credentialType, enabled: true, value, username };
}

describe("OpenAPI credential drafts", () => {
  it("serializes every supported credential without changing OAuth field names", () => {
    expect(
      buildCredentialMap([
        draft("key", "api_key", "key-secret"),
        draft("bearer", "bearer", "bearer-secret"),
        draft("basic", "basic", "password", "davis"),
        draft("oauth", "oauth_access_token", "oauth-secret"),
      ]),
    ).toEqual({
      key: { type: "api_key", value: "key-secret" },
      bearer: { type: "bearer", token: "bearer-secret" },
      basic: { type: "basic", username: "davis", password: "password" },
      oauth: { type: "oauth_access_token", access_token: "oauth-secret" },
    });
  });

  it("ignores disabled preview schemes", () => {
    expect(
      buildCredentialMap([{ ...draft("unused", "bearer", "secret"), enabled: false }]),
    ).toEqual({});
  });

  it("rejects duplicate trimmed scheme names without dropping a secret", () => {
    const rows = [draft("auth", "bearer", "one"), draft(" auth ", "bearer", "two")];
    expect(duplicateCredentialNames(rows)).toEqual(["auth"]);
    expect(buildCredentialMap(rows)).toBeNull();
  });

  it("rejects enabled credentials with missing names or secret values", () => {
    expect(buildCredentialMap([draft("", "api_key", "secret")])).toBeNull();
    expect(buildCredentialMap([draft("auth", "api_key", "")])).toBeNull();
  });
});
