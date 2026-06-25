import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { ApiError, type ApiResult, type Source } from "./api";
import GraphqlSourceForm from "./GraphqlSourceForm.svelte";
import type { GraphqlSourceInput } from "./graphql-source-state";

function sourceFixture(): Source {
  return {
    id: "graphql-source",
    kind: "graphql",
    slug: "product",
    displayName: "Product API",
    description: null,
    configuration: { endpoint: "https://api.example.test/graphql", allowPrivateNetwork: false },
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

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

async function fillRequiredFields() {
  await fireEvent.input(screen.getByLabelText("Endpoint"), {
    target: { value: "https://api.example.test/graphql" },
  });
  await fireEvent.input(screen.getByLabelText("Source name"), {
    target: { value: "Product API" },
  });
}

afterEach(cleanup);

describe("GraphQL source form", () => {
  it("submits the stable source contract and clears the completed draft", async () => {
    const inputs: GraphqlSourceInput[] = [];
    const create = vi.fn(async (input: GraphqlSourceInput) => {
      inputs.push(input);
      return { ok: true, value: sourceFixture() } as const;
    });
    const created = vi.fn();
    render(GraphqlSourceForm, { create, oncreated: created });
    await fillRequiredFields();
    await fireEvent.input(screen.getByLabelText("Preferred slug (optional)"), {
      target: { value: " product " },
    });
    await fireEvent.change(screen.getByLabelText("Method"), { target: { value: "bearer" } });
    await fireEvent.input(screen.getByLabelText("Bearer token"), {
      target: { value: " exact token " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(created).toHaveBeenCalledOnce());
    expect(inputs).toEqual([
      {
        kind: "graphql",
        displayName: "Product API",
        preferredSlug: "product",
        endpoint: "https://api.example.test/graphql",
        allowPrivateNetwork: false,
        credential: { type: "bearer", token: " exact token " },
      },
    ]);
    expect(screen.getByLabelText<HTMLInputElement>("Endpoint").value).toBe("");
    expect(document.body.textContent).not.toContain("exact token");
  });

  it("rejects query-bearing endpoints before serialization", async () => {
    const create = vi.fn();
    render(GraphqlSourceForm, { create, oncreated: vi.fn() });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://api.example.test/graphql?token=do-not-store" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });

    expect(screen.getByText(/without user info, query parameters, or fragments/)).toBeDefined();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect source" }).disabled).toBe(
      true,
    );
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects credential-bearing remote plaintext endpoints", async () => {
    const create = vi.fn();
    render(GraphqlSourceForm, { create, oncreated: vi.fn() });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "http://api.example.test/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });
    await fireEvent.change(screen.getByLabelText("Method"), { target: { value: "bearer" } });
    await fireEvent.input(screen.getByLabelText("Bearer token"), {
      target: { value: "do-not-send-in-cleartext" },
    });

    expect(screen.getByText(/Plain HTTP is allowed only for loopback/)).toBeDefined();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect source" }).disabled).toBe(
      true,
    );
    expect(create).not.toHaveBeenCalled();
  });

  it("blocks an obvious private endpoint until the operator opts in", async () => {
    const create = vi.fn();
    render(GraphqlSourceForm, { create, oncreated: vi.fn() });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "http://127.0.0.1:4000/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local GraphQL" },
    });

    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect source" }).disabled).toBe(
      true,
    );
    expect(screen.getByText(/Enable private network access/)).toBeDefined();
    expect(create).not.toHaveBeenCalled();
  });

  it("aborts on unmount and rejects the late completion", async () => {
    const response = deferred<ApiResult<Source>>();
    const request = { signal: null as AbortSignal | null };
    const create = vi.fn((_input: GraphqlSourceInput, signal: AbortSignal) => {
      request.signal = signal;
      return response.promise;
    });
    const created = vi.fn();
    const mounted = render(GraphqlSourceForm, { create, oncreated: created });
    await fillRequiredFields();
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));
    mounted.unmount();

    expect(request.signal?.aborted).toBe(true);
    response.resolve({ ok: true, value: sourceFixture() });
    await response.promise;
    await Promise.resolve();
    expect(created).not.toHaveBeenCalled();
  });

  it("keeps busy until the coordinator settles and focuses a recovery failure", async () => {
    const response = deferred<ApiResult<Source>>();
    const create = vi.fn(() => response.promise);
    const busy = vi.fn();
    render(GraphqlSourceForm, {
      create,
      onbusychange: busy,
      oncreated: vi.fn(),
    });
    await fillRequiredFields();
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(busy).toHaveBeenLastCalledWith(true));
    response.resolve({
      ok: false,
      error: new ApiError({
        code: "source_create_recovery_pending",
        displayMessage: "Source recovery is pending.",
        requestId: null,
        status: 0,
      }),
    });
    await response.promise;
    await waitFor(() => expect(busy).toHaveBeenLastCalledWith(false));
    expect(screen.getByText("Source recovery is pending.")).toBeDefined();
    expect(document.activeElement).toBe(document.getElementById("graphql-source-error"));
    expect(create).toHaveBeenCalledOnce();
  });

  it("clears secrets and focuses a rejected request", async () => {
    const create = vi.fn(
      async () =>
        ({
          ok: false,
          error: new ApiError({
            code: "graphql_introspection_failed",
            displayMessage: "GraphQL introspection failed.",
            requestId: "request-1",
            status: 422,
          }),
        }) as const,
    );
    render(GraphqlSourceForm, { create, oncreated: vi.fn() });
    await fillRequiredFields();
    await fireEvent.change(screen.getByLabelText("Method"), { target: { value: "bearer" } });
    const secret = screen.getByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(secret, { target: { value: "clear-me" } });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(secret.value).toBe("");
    expect(document.body.textContent).not.toContain("clear-me");
    expect(document.activeElement).toBe(document.getElementById("graphql-source-error"));
  });
});
