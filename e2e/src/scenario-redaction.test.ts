import { expect, it } from "@effect/vitest";

import { redactFailureText } from "./scenario";

it("removes setup, API, cookie, CSRF, and password credentials from persisted failures", () => {
  const secret = [
    "http://127.0.0.1/setup#token=setup-secret",
    "Authorization: Bearer bearer-secret",
    "exr_token-secret",
    "Cookie: executor_session=session-secret; executor_csrf=csrf-secret",
    "x-executor-csrf: csrf-secret",
    '{"password":"password-secret","setupToken":"setup-secret"}',
    "http://127.0.0.1/callback?code=code-secret&state=state-secret&code_verifier=verifier-secret&code_challenge=challenge-secret",
    '{"access_token":"access-secret","refresh_token":"refresh-secret","clientSecret":"client-secret","apiToken":"api-secret"}',
  ].join("\n");
  const redacted = redactFailureText(secret);
  for (const value of [
    "setup-secret",
    "bearer-secret",
    "token-secret",
    "session-secret",
    "csrf-secret",
    "password-secret",
    "code-secret",
    "state-secret",
    "verifier-secret",
    "challenge-secret",
    "access-secret",
    "refresh-secret",
    "client-secret",
    "api-secret",
  ]) {
    expect(redacted).not.toContain(value);
  }
  expect(redacted).toContain("[REDACTED]");
});
