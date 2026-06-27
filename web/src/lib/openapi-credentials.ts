import type { OpenApiStaticCredential } from "$lib/api";

export type SupportedCredentialType = "api_key" | "bearer" | "basic" | "oauth_access_token";

export type CredentialDraft = {
  key: string;
  name: string;
  credentialType: SupportedCredentialType;
  enabled: boolean;
  value: string;
  username: string;
};

export function buildCredentialMap(rows: readonly CredentialDraft[]) {
  const credentials: Record<string, OpenApiStaticCredential> = {};
  const names = new Set<string>();
  for (const row of rows) {
    if (!row.enabled) continue;
    const name = row.name.trim();
    if (name === "" || row.value === "" || names.has(name)) return null;
    names.add(name);
    if (row.credentialType === "api_key") {
      credentials[name] = { type: "api_key", value: row.value };
    } else if (row.credentialType === "bearer") {
      credentials[name] = { type: "bearer", token: row.value };
    } else if (row.credentialType === "oauth_access_token") {
      credentials[name] = { type: "oauth_access_token", access_token: row.value };
    } else {
      credentials[name] = { type: "basic", username: row.username, password: row.value };
    }
  }
  return credentials;
}

export function duplicateCredentialNames(rows: readonly CredentialDraft[]) {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const row of rows) {
    if (!row.enabled) continue;
    const name = row.name.trim();
    if (name !== "" && seen.has(name)) duplicates.add(name);
    seen.add(name);
  }
  return [...duplicates];
}

export function isSupportedCredentialType(value: string): value is SupportedCredentialType {
  return ["api_key", "bearer", "basic", "oauth_access_token"].includes(value);
}
