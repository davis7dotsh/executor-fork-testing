import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { ApiError, type ApiResult, type OpenApiCredentialMetadata, type Source } from "./api";
import GraphqlCredentialEditor from "./GraphqlCredentialEditor.svelte";
import type { GraphqlCredential } from "./graphql-source-state";

function sourceFixture(id = "graphql-source"): Source {
  return {
    id,
    kind: "graphql",
    slug: "product",
    displayName: "Product API",
    description: null,
    configuration: {
      endpoint: "https://api.example.test/graphql?token=hidden",
      allowPrivateNetwork: false,
    },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 4,
    tombstonedToolCount: 0,
  };
}

function metadata(
  revision: number,
  credentialType: "bearer" | "basic" | "api_key_header" | "oauth_access_token" = "bearer",
): OpenApiCredentialMetadata {
  return {
    revision,
    configuredSchemes: [{ name: "default", credentialType }],
  };
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

afterEach(cleanup);

describe("GraphQL credential editor", () => {
  it("replaces credentials with the metadata CAS revision", async () => {
    const load = vi.fn(async () => ({ ok: true, value: metadata(4) }) as const);
    const saves: Array<{ revision: number; credential: GraphqlCredential }> = [];
    const save = vi.fn(
      async (_sourceId: string, revision: number, credential: GraphqlCredential) => {
        saves.push({ revision, credential });
        return { ok: true, value: metadata(5, "api_key_header") } as const;
      },
    );
    render(GraphqlCredentialEditor, { source: sourceFixture(), load, save });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const method = await screen.findByLabelText("Method");
    await fireEvent.change(method, { target: { value: "api_key_header" } });
    await fireEvent.input(screen.getByLabelText("Header name"), {
      target: { value: " X-Service-Key " },
    });
    await fireEvent.input(screen.getByLabelText("Header value"), {
      target: { value: " exact key " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(saves).toEqual([
      {
        revision: 4,
        credential: { type: "api_key_header", name: "X-Service-Key", value: " exact key " },
      },
    ]);
    expect(document.body.textContent).not.toContain("exact key");
    expect(document.body.textContent).not.toContain("token=hidden");
    expect(document.activeElement).toBe(
      document.getElementById("graphql-credential-status-graphql-source"),
    );
  });

  it("requires explicit confirmation and clears credentials with CAS", async () => {
    const load = vi.fn(async () => ({ ok: true, value: metadata(7) }) as const);
    const save = vi.fn(async () => ({ ok: true, value: metadata(8) }) as const);
    render(GraphqlCredentialEditor, { source: sourceFixture(), load, save });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await screen.findByLabelText("Method");
    await fireEvent.click(screen.getByRole("button", { name: "Clear credentials" }));
    expect(document.activeElement).toBe(
      document.getElementById("graphql-cancel-clear-graphql-source"),
    );
    await fireEvent.click(screen.getByRole("button", { name: "Confirm clear" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(save).toHaveBeenCalledWith("graphql-source", 7, null, expect.any(AbortSignal));
  });

  it("clears secret input and disables saving after a CAS conflict", async () => {
    const load = vi.fn(async () => ({ ok: true, value: metadata(4) }) as const);
    const save = vi.fn(
      async () =>
        ({
          ok: false,
          error: new ApiError({
            code: "revision_conflict",
            displayMessage: "Credentials changed elsewhere.",
            requestId: "request-conflict",
            status: 409,
          }),
        }) as const,
    );
    render(GraphqlCredentialEditor, { source: sourceFixture(), load, save });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const secret = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(secret, { target: { value: "clear-after-conflict" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    await waitFor(() => expect(screen.queryByLabelText("Bearer token")).toBeNull());
    expect(document.body.textContent).not.toContain("clear-after-conflict");
    expect(document.activeElement).toBe(
      document.getElementById("graphql-credential-error-graphql-source"),
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
  });

  it("aborts metadata loading and ignores its completion after unmount", async () => {
    const response = deferred<ApiResult<OpenApiCredentialMetadata>>();
    const request = { signal: null as AbortSignal | null };
    const load = vi.fn((_sourceId: string, signal: AbortSignal) => {
      request.signal = signal;
      return response.promise;
    });
    const save = vi.fn();
    const mounted = render(GraphqlCredentialEditor, { source: sourceFixture(), load, save });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    mounted.unmount();

    expect(request.signal?.aborted).toBe(true);
    response.resolve({ ok: true, value: metadata(3) });
    await response.promise;
    await Promise.resolve();
    expect(save).not.toHaveBeenCalled();
  });

  it("aborts an old metadata load and rejects it after the source changes", async () => {
    const first = deferred<ApiResult<OpenApiCredentialMetadata>>();
    const second = deferred<ApiResult<OpenApiCredentialMetadata>>();
    const firstRequest = { signal: null as AbortSignal | null };
    const load = vi.fn((sourceId: string, signal: AbortSignal) => {
      if (sourceId === "source-a") {
        firstRequest.signal = signal;
        return first.promise;
      }
      return second.promise;
    });
    const save = vi.fn();
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture("source-a"),
      load,
      save,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await mounted.rerender({ source: sourceFixture("source-b"), load, save });

    await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
    expect(firstRequest.signal?.aborted).toBe(true);
    second.resolve({ ok: true, value: metadata(8, "basic") });
    await screen.findByLabelText("Username");
    first.resolve({ ok: true, value: metadata(3, "bearer") });
    await first.promise;
    await Promise.resolve();
    expect(screen.queryByLabelText("Bearer token")).toBeNull();
  });

  it("reloads the CAS revision before saving after an open source changes", async () => {
    const load = vi.fn(async (sourceId: string) =>
      sourceId === "source-a"
        ? ({ ok: true, value: metadata(4) } as const)
        : ({ ok: true, value: metadata(9, "basic") } as const),
    );
    const save = vi.fn(async () => ({ ok: true, value: metadata(10, "basic") }) as const);
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture("source-a"),
      load,
      save,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await screen.findByLabelText("Bearer token");
    await mounted.rerender({ source: sourceFixture("source-b"), load, save });
    await screen.findByLabelText("Username");
    await fireEvent.input(screen.getByLabelText("Username"), { target: { value: "operator" } });
    await fireEvent.input(screen.getByLabelText("Password"), { target: { value: "password" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save).toHaveBeenCalledWith(
      "source-b",
      9,
      { type: "basic", username: "operator", password: "password" },
      expect.any(AbortSignal),
    );
  });

  it("aborts a pending save and rejects its completion after the source changes", async () => {
    const pendingSave = deferred<ApiResult<OpenApiCredentialMetadata>>();
    const saveRequest = { signal: null as AbortSignal | null };
    const load = vi.fn(async (sourceId: string) =>
      sourceId === "source-a"
        ? ({ ok: true, value: metadata(4) } as const)
        : ({ ok: true, value: metadata(9, "basic") } as const),
    );
    const save = vi.fn(
      (
        _sourceId: string,
        _revision: number,
        _credential: GraphqlCredential,
        signal: AbortSignal,
      ) => {
        saveRequest.signal = signal;
        return pendingSave.promise;
      },
    );
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture("source-a"),
      load,
      save,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "source-a-token" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await mounted.rerender({ source: sourceFixture("source-b"), load, save });

    await screen.findByLabelText("Username");
    expect(saveRequest.signal?.aborted).toBe(true);
    pendingSave.resolve({ ok: true, value: metadata(5) });
    await pendingSave.promise;
    await Promise.resolve();
    expect(screen.getByRole("button", { name: "Close credentials" })).toBeDefined();
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.queryByLabelText("Bearer token")).toBeNull();
  });

  it("clears a completed source notice when the source identity changes", async () => {
    const load = vi.fn(async () => ({ ok: true, value: metadata(4) }) as const);
    const save = vi.fn(async () => ({ ok: true, value: metadata(5) }) as const);
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture("source-a"),
      load,
      save,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "source-a-token" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());

    await mounted.rerender({ source: sourceFixture("source-b"), load, save });
    await waitFor(() => expect(screen.queryByRole("status")).toBeNull());
    expect(screen.getByRole("button", { name: "Manage credentials" })).toBeDefined();
  });

  it("disables an open editor while a card operation is active", async () => {
    const load = vi.fn(async () => ({ ok: true, value: metadata(4) }) as const);
    const save = vi.fn();
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture(),
      load,
      save,
      disabled: false,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const method = await screen.findByLabelText<HTMLSelectElement>("Method");
    await mounted.rerender({ source: sourceFixture(), load, save, disabled: true });

    await waitFor(() => expect(method.closest("fieldset")?.hasAttribute("disabled")).toBe(true));
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Close credentials" }).disabled,
    ).toBe(true);
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Clear credentials" }).disabled,
    ).toBe(true);
    expect(save).not.toHaveBeenCalled();
  });

  it("reports save activity and aborts it when an external card operation starts", async () => {
    const response = deferred<ApiResult<OpenApiCredentialMetadata>>();
    const request = { signal: null as AbortSignal | null };
    const load = vi.fn(async () => ({ ok: true, value: metadata(4) }) as const);
    const save = vi.fn(
      (
        _sourceId: string,
        _revision: number,
        _credential: GraphqlCredential,
        signal: AbortSignal,
      ) => {
        request.signal = signal;
        return response.promise;
      },
    );
    const onbusychange = vi.fn();
    const mounted = render(GraphqlCredentialEditor, {
      source: sourceFixture(),
      load,
      save,
      onbusychange,
      disabled: false,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "credential-secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(onbusychange).toHaveBeenLastCalledWith(true));

    await mounted.rerender({
      source: sourceFixture(),
      load,
      save,
      onbusychange,
      disabled: true,
    });
    await waitFor(() => expect(request.signal?.aborted).toBe(true));
    await waitFor(() => expect(onbusychange).toHaveBeenLastCalledWith(false));
    expect(document.body.textContent).not.toContain("credential-secret");
    response.resolve({ ok: true, value: metadata(5) });
    await response.promise;
  });
});
