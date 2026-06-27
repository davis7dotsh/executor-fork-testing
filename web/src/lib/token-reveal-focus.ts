import { tick } from "svelte";
import type { CreatedToken } from "./api";

export async function focusRevealedToken(input: {
  token: CreatedToken;
  currentToken: () => CreatedToken | null;
  field: () => HTMLInputElement | undefined;
  isCurrentLifetime: () => boolean;
}) {
  await tick();
  if (!input.isCurrentLifetime() || input.currentToken() !== input.token) return;

  const field = input.field();
  if (field === undefined) return;
  field.focus();
  field.select();
}
