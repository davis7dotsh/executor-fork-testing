import { afterEach, describe, expect, it } from "@effect/vitest";
import { focusRevealedToken } from "./token-reveal-focus";

const token = {
  id: "token-1",
  name: "Laptop agent",
  token: "exr_public_secret",
  createdAt: 1_750_000_000,
};

afterEach(() => {
  document.body.replaceChildren();
});

describe("one-time token focus", () => {
  it("focuses and selects the revealed token after its input renders", async () => {
    const previous = document.createElement("button");
    const field = document.createElement("input");
    field.readOnly = true;
    field.value = token.token;
    document.body.append(previous, field);
    previous.focus();

    await focusRevealedToken({
      token,
      currentToken: () => token,
      field: () => field,
      isCurrentLifetime: () => true,
    });

    expect(document.activeElement).toBe(field);
    expect(field.selectionStart).toBe(0);
    expect(field.selectionEnd).toBe(token.token.length);
  });

  it("leaves focus alone for a stale lifetime or replaced token", async () => {
    const previous = document.createElement("button");
    const field = document.createElement("input");
    document.body.append(previous, field);
    previous.focus();

    await focusRevealedToken({
      token,
      currentToken: () => token,
      field: () => field,
      isCurrentLifetime: () => false,
    });
    await focusRevealedToken({
      token,
      currentToken: () => null,
      field: () => field,
      isCurrentLifetime: () => true,
    });

    expect(document.activeElement).toBe(previous);
  });
});
