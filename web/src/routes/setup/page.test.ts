import { expect, it } from "@effect/vitest";
import { render, screen, waitFor } from "@testing-library/svelte";
import Page from "./+page.svelte";

it("removes the first-boot token from browser history without rendering it", async () => {
  history.replaceState({}, "", "/setup#token=set_test_secret");
  render(Page);

  await waitFor(() => expect(window.location.hash).toBe(""));
  expect(screen.getByRole("heading", { name: "Make this instance yours." })).toBeDefined();
  expect(document.body.textContent).not.toContain("set_test_secret");
});
