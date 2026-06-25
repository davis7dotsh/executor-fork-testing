import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";

const mocks = {
  goto: vi.fn(async () => {}),
  signOut: vi.fn(async () => ({ ok: true as const, value: undefined })),
};

vi.doMock("$app/navigation", () => ({ goto: mocks.goto }));
vi.doMock("$app/state", () => ({ page: { url: new URL("http://localhost/tokens") } }));
vi.doMock("$lib/auth.svelte", () => ({
  useAuthState: () => ({ username: "admin", signOut: mocks.signOut }),
}));

const { default: DashboardShell } = await import("./DashboardShell.svelte");
const children = createRawSnippet(() => ({ render: () => "<p>Page content</p>" }));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("dashboard sign out", () => {
  it("consults a page guard before destroying the session", async () => {
    let allowSignOut = false;
    const beforeSignOut = vi.fn(() => allowSignOut);
    render(DashboardShell, {
      title: "API tokens",
      description: "Manage API tokens.",
      children,
      beforeSignOut,
    });

    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(beforeSignOut).toHaveBeenCalledOnce();
    expect(mocks.signOut).not.toHaveBeenCalled();
    expect(mocks.goto).not.toHaveBeenCalled();

    allowSignOut = true;
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(mocks.signOut).toHaveBeenCalledOnce());
    expect(beforeSignOut).toHaveBeenCalledTimes(2);
    expect(mocks.goto).toHaveBeenCalledWith("/login", { replaceState: true });
  });

  it("signs out normally when a page does not provide a guard", async () => {
    render(DashboardShell, {
      title: "Sources",
      description: "Manage sources.",
      children,
    });

    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(mocks.signOut).toHaveBeenCalledOnce());
    expect(mocks.goto).toHaveBeenCalledWith("/login", { replaceState: true });
  });
});
