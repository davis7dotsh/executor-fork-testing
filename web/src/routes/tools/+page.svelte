<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { tick, untrack } from "svelte";
  import DashboardShell from "$lib/DashboardShell.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import {
    bulkSetToolModes,
    getTool,
    listSources,
    listTools,
    setToolMode,
    type ApiError,
    type SourceList,
    type ToolMode,
    type ToolPage,
    type ToolRecord,
  } from "$lib/api";
  import {
    beginIdentityResourceLoad,
    beginResourceLoad,
    createLatestRequest,
    emptyResource,
    modeLabel,
    provenanceLabel,
    settleResourceLoad,
    toolModes,
    unexpectedRequestError,
  } from "$lib/catalog-state";
  import { parseToolsUrl, toolsListKey, toolsUrl } from "$lib/catalog-url";
  import {
    broadConfirmationText,
    bulkActionLabel,
    inheritLabel,
    modeName,
    requiresBroadConfirmation,
  } from "$lib/catalog-ux";

  const auth = useAuthState();
  const pageRequest = createLatestRequest();
  const sourceRequest = createLatestRequest();
  const detailRequest = createLatestRequest();
  let searchKey = $derived(page.url.search);
  let urlState = $derived(parseToolsUrl(new URLSearchParams(searchKey)));
  let listSearch = $derived(toolsUrl(urlState, { tool: null }));
  let listKey = $derived(toolsListKey(urlState));
  let resource = $state(emptyResource<ToolPage>());
  let listIdentity = $state<string | null>(null);
  let sources = $state(emptyResource<SourceList>());
  let detail = $state(emptyResource<ToolRecord>());
  let detailIdentity = $state<string | null>(null);
  let refreshKey = $state(0);
  let detailRefreshKey = $state(0);
  let selected = $state<string[]>([]);
  let pending = $state<string[]>([]);
  let mutationErrors = $state<Record<string, ApiError>>({});
  let conflictNotice = $state<string | null>(null);
  let bulkNotice = $state<string | null>(null);
  let bulkMode = $state<ToolMode>("ask");
  let confirmingBulk = $state<{
    mode: ToolMode;
    ids: string[];
    catalogRevision: number;
  } | null>(null);
  let searchInput = $state<HTMLInputElement>();
  let searchForm = $state<HTMLFormElement>();
  let selectAllInput = $state<HTMLInputElement>();
  let detailReturnId = $state<string | null>(null);
  const mutationControllers = new Map<string, AbortController>();

  $effect(() => {
    const identity = listKey;
    const search = listSearch;
    const requestKey = `${identity}\u0000${refreshKey}`;
    const parameters = new URL(search, "http://executor.local").searchParams;
    const filters = parseToolsUrl(parameters);
    const started = beginIdentityResourceLoad(
      untrack(() => resource),
      untrack(() => listIdentity),
      identity,
    );
    if (untrack(() => listIdentity) !== identity) {
      selected = [];
      confirmingBulk = null;
    }
    listIdentity = started.identity;
    resource = started.state;
    return pageRequest.start(
      async (signal) => ({
        requestKey,
        result: await listTools(
          {
            query: filters.q,
            sourceId: filters.source ?? undefined,
            mode: filters.mode ?? undefined,
            includeTombstoned: filters.removed,
            limit: 50,
            offset: filters.offset,
          },
          undefined,
          signal,
        ),
      }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== `${listKey}\u0000${refreshKey}`) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        resource = settleResourceLoad(resource, result);
        if (result.ok) {
          const visible = new Set(
            result.value.items.filter((tool) => tool.present).map((tool) => tool.id),
          );
          selected = selected.filter((id) => visible.has(id));
        }
      },
      () => {
        resource = settleResourceLoad(resource, {
          ok: false,
          error: unexpectedRequestError(),
        });
      },
    );
  });

  $effect(() => {
    const toolId = urlState.tool;
    const returnId = untrack(() => detailReturnId);
    void tick().then(() => {
      if (toolId !== null) {
        document.getElementById("tool-detail-panel")?.focus();
      } else if (returnId !== null) {
        document.getElementById(`inspect-tool-${returnId}`)?.focus();
        detailReturnId = null;
      }
    });
  });

  $effect(() => {
    const requestKey = String(refreshKey);
    sources = beginResourceLoad(untrack(() => sources));
    return sourceRequest.start(
      async (signal) => ({ requestKey, result: await listSources(undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== String(refreshKey)) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        sources = settleResourceLoad(sources, result);
      },
      () => {
        sources = settleResourceLoad(sources, {
          ok: false,
          error: unexpectedRequestError(),
        });
      },
    );
  });

  $effect(() => {
    const toolId = urlState.tool;
    const requestKey = `${toolId ?? ""}\u0000${refreshKey}\u0000${detailRefreshKey}`;
    if (toolId === null) {
      detail = emptyResource<ToolRecord>();
      detail = { ...detail, loading: false };
      detailIdentity = null;
      return;
    }
    const started = beginIdentityResourceLoad(
      untrack(() => detail),
      untrack(() => detailIdentity),
      toolId,
    );
    detailIdentity = started.identity;
    detail = started.state;
    return detailRequest.start(
      async (signal) => ({ requestKey, result: await getTool(toolId, undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== `${urlState.tool ?? ""}\u0000${refreshKey}\u0000${detailRefreshKey}`)
          return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        detail = settleResourceLoad(detail, result, { retainDataOnError: false });
      },
      () => {
        detail = settleResourceLoad(
          detail,
          { ok: false, error: unexpectedRequestError() },
          { retainDataOnError: false },
        );
      },
    );
  });

  $effect(() => () => {
    for (const controller of mutationControllers.values()) controller.abort();
  });

  $effect(() => {
    const input = selectAllInput;
    const activeIds =
      resource.data?.items.filter((tool) => tool.present).map((tool) => tool.id) ?? [];
    const selectedCount = activeIds.filter((id) => selected.includes(id)).length;
    if (input !== undefined)
      input.indeterminate = selectedCount > 0 && selectedCount < activeIds.length;
  });

  async function changeToolMode(
    tool: ToolRecord | ToolPage["items"][number],
    mode: ToolMode | null,
  ) {
    const controller = beginMutation(tool.id);
    conflictNotice = null;
    const result = await setToolMode(tool.id, mode, tool.revision, undefined, controller.signal);
    if (!finishMutation(tool.id, controller)) return;
    if (!result.ok) {
      handleMutationError(tool.id, result.error);
      return;
    }
    refreshKey += 1;
  }

  async function applyBulkMode(
    mode: ToolMode | null,
    ids: string[],
    expectedCatalogRevision: number,
  ) {
    if (ids.length === 0 || resource.data === null || resource.loading) return;
    const controller = beginMutation("bulk");
    conflictNotice = null;
    bulkNotice = null;
    const result = await bulkSetToolModes(
      ids.slice(0, 200),
      mode,
      expectedCatalogRevision,
      undefined,
      controller.signal,
    );
    if (!finishMutation("bulk", controller)) return;
    if (!result.ok) {
      handleMutationError("bulk", result.error);
      return;
    }
    confirmingBulk = null;
    bulkNotice = `${mode === null ? "Inherit" : modeName(mode)} applied to ${ids.length} selected ${ids.length === 1 ? "tool" : "tools"}.`;
    selected = [];
    refreshKey += 1;
    await tick();
    document.getElementById("bulk-status")?.focus();
  }

  function requestBulkMode(mode: ToolMode | null) {
    if (selected.length === 0 || resource.data === null || resource.loading) return;
    const snapshot = {
      mode,
      ids: selected.slice(0, 200),
      catalogRevision: resource.data.catalogRevision,
    };
    if (mode !== null && requiresBroadConfirmation(mode)) {
      confirmingBulk = { ...snapshot, mode };
      void tick().then(() => document.getElementById("cancel-bulk-mode")?.focus());
      return;
    }
    void applyBulkMode(mode, snapshot.ids, snapshot.catalogRevision);
  }

  function confirmBulkMode() {
    const confirmation = confirmingBulk;
    if (confirmation === null) return;
    void applyBulkMode(confirmation.mode, confirmation.ids, confirmation.catalogRevision);
  }

  async function cancelBulkConfirmation() {
    confirmingBulk = null;
    await tick();
    document.getElementById("bulk-apply-mode")?.focus();
  }

  function inheritedMode(tool: ToolPage["items"][number]) {
    if (tool.modeOverride === null) return tool.effectiveMode.mode;
    if (sources.loading || sources.error !== null || sources.data === null) return null;
    const source = sources.data.sources.find((candidate) => candidate.id === tool.sourceId);
    if (source === undefined) return null;
    return source.modeOverride ?? tool.intrinsicMode;
  }

  function handleMutationError(id: string, error: ApiError) {
    if (auth.recoverFromApiError(error)) return;
    if (error.status === 409) {
      conflictNotice = "Tool settings changed elsewhere. The latest catalog is shown for review.";
      if (id === "bulk") confirmingBulk = null;
      refreshKey += 1;
      void tick().then(() => document.getElementById("tool-conflict")?.focus());
    } else {
      mutationErrors = { ...mutationErrors, [id]: error };
    }
  }

  function beginMutation(id: string) {
    mutationControllers.get(id)?.abort();
    const controller = new AbortController();
    mutationControllers.set(id, controller);
    pending = [...new Set([...pending, id])];
    const { [id]: _removed, ...rest } = mutationErrors;
    mutationErrors = rest;
    return controller;
  }

  function finishMutation(id: string, controller: AbortController) {
    if (mutationControllers.get(id) !== controller || controller.signal.aborted) return false;
    mutationControllers.delete(id);
    pending = pending.filter((candidate) => candidate !== id);
    return true;
  }

  function toggleSelected(id: string, checked: boolean) {
    selected = checked
      ? [...new Set([...selected, id])].slice(0, 200)
      : selected.filter((candidate) => candidate !== id);
  }

  function toggleCurrentPage(checked: boolean) {
    const visible =
      resource.data?.items.filter((tool) => tool.present).map((tool) => tool.id) ?? [];
    selected = checked ? visible.slice(0, 200) : selected.filter((id) => !visible.includes(id));
  }

  function submitFilters(event: Event) {
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const next = {
      ...urlState,
      q: String(data.get("q") ?? "").slice(0, 256),
      source: String(data.get("source") ?? "") || null,
      mode: (String(data.get("mode") ?? "") || null) as ToolMode | null,
      removed: data.get("removed") === "1",
      offset: 0,
      tool: null,
    };
    event.preventDefault();
    void goto(toolsUrl(next), { keepFocus: true, noScroll: true });
  }

  function handleShortcut(event: KeyboardEvent) {
    const target = event.target;
    const editable =
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement ||
      (target instanceof HTMLElement && target.isContentEditable);
    if (event.key === "/" && !editable) {
      event.preventDefault();
      searchInput?.focus();
    } else if (
      event.key === "Escape" &&
      document.activeElement === searchInput &&
      searchInput?.value
    ) {
      searchInput.value = "";
      searchForm?.requestSubmit();
    }
  }

  function detailUrl(toolId: string | null) {
    return toolsUrl(urlState, { tool: toolId });
  }
</script>

<svelte:window onkeydown={handleShortcut} />

<DashboardShell title="Tools" description="Find and control the capabilities agents can use.">
  <form class="surface filter-bar" method="GET" bind:this={searchForm} onsubmit={submitFilters}>
    <label class="search-field">
      Search tools
      <input
        bind:this={searchInput}
        name="q"
        value={urlState.q}
        placeholder="Name, path, or description"
      />
    </label>
    <label>
      Source
      <select
        name="source"
        value={urlState.source ?? ""}
        onchange={() => searchForm?.requestSubmit()}
      >
        <option value="">All sources</option>
        {#each sources.data?.sources ?? [] as source (source.id)}
          <option value={source.id}>{source.displayName}</option>
        {/each}
        {#if urlState.source !== null && !sources.data?.sources.some((source) => source.id === urlState.source)}
          <option value={urlState.source}>Current source ({urlState.source})</option>
        {/if}
      </select>
    </label>
    <label>
      Effective mode
      <select name="mode" value={urlState.mode ?? ""} onchange={() => searchForm?.requestSubmit()}>
        <option value="">All modes</option>
        {#each toolModes as mode}<option value={mode}>{modeLabel(mode)}</option>{/each}
      </select>
    </label>
    <label class="checkbox-label">
      <input
        type="checkbox"
        name="removed"
        value="1"
        checked={urlState.removed}
        onchange={() => searchForm?.requestSubmit()}
      />
      Include removed
    </label>
    <button type="submit" class="primary">Search</button>
  </form>
  {#if sources.error !== null}
    <div class="notice warning" role="status">
      Source names could not be loaded. The active source filter is still applied.
    </div>
  {/if}

  <section class="surface mode-semantics" aria-labelledby="mode-semantics-title">
    <div>
      <p class="eyebrow">Behavior semantics</p>
      <h2 id="mode-semantics-title">How tool modes work</h2>
    </div>
    <dl>
      <div>
        <dt>Inherit</dt>
        <dd>Follow the source default, then the tool's built-in default.</dd>
      </div>
      <div>
        <dt>Enabled</dt>
        <dd>Available without interactive approval.</dd>
      </div>
      <div>
        <dt>Ask</dt>
        <dd>Require interactive approval before execution.</dd>
      </div>
      <div>
        <dt>Disabled</dt>
        <dd>Unavailable to gateway callers.</dd>
      </div>
    </dl>
  </section>

  {#if conflictNotice !== null}<div
      id="tool-conflict"
      class="notice warning"
      role="status"
      tabindex="-1"
    >
      {conflictNotice}
    </div>{/if}
  {#if resource.stale && resource.error !== null}
    <div class="stale-notice" role="status">
      Showing the last loaded tool page while Executor reconnects.
      <ErrorNotice error={resource.error} />
    </div>
  {:else if resource.error !== null}
    <section class="surface table-unavailable">
      <ErrorNotice error={resource.error} />
      <button type="button" onclick={() => (refreshKey += 1)}>Try again</button>
    </section>
  {/if}

  {#if resource.data !== null}
    <section class="surface bulk-bar" aria-label="Bulk tool behavior">
      <div>
        <strong>{selected.length} selected on this page</strong>
        <small>Bulk changes use catalog revision {resource.data.catalogRevision}.</small>
      </div>
      <fieldset
        class="mode-control compact"
        disabled={resource.loading || selected.length === 0 || pending.includes("bulk")}
      >
        <legend>Set selected tools</legend>
        {#each toolModes as mode}
          <label
            ><input type="radio" name="bulk-mode" value={mode} bind:group={bulkMode} />{modeLabel(
              mode,
            )}</label
          >
        {/each}
      </fieldset>
      <div class="button-row">
        <button
          id="bulk-apply-mode"
          type="button"
          class:primary={bulkMode === "enabled"}
          class:danger-button={bulkMode === "disabled"}
          disabled={resource.loading || selected.length === 0 || pending.includes("bulk")}
          onclick={() => requestBulkMode(bulkMode)}
          >{bulkActionLabel(bulkMode, selected.length)}</button
        >
        <button
          type="button"
          disabled={resource.loading || selected.length === 0 || pending.includes("bulk")}
          onclick={() => requestBulkMode(null)}>{bulkActionLabel(null, selected.length)}</button
        >
      </div>
      {#if confirmingBulk !== null}
        <div
          class="inline-confirm bulk-confirm"
          role="group"
          aria-label="Confirm bulk tool behavior"
        >
          <strong>{broadConfirmationText(confirmingBulk.mode, confirmingBulk.ids.length)}</strong>
          <button
            id="cancel-bulk-mode"
            type="button"
            disabled={pending.includes("bulk")}
            onkeydown={(event) => {
              if (event.key === "Escape") void cancelBulkConfirmation();
            }}
            onclick={cancelBulkConfirmation}>Cancel</button
          >
          <button
            type="button"
            class:primary={confirmingBulk.mode === "enabled"}
            class:danger-button={confirmingBulk.mode === "disabled"}
            disabled={pending.includes("bulk")}
            onkeydown={(event) => {
              if (event.key === "Escape") void cancelBulkConfirmation();
            }}
            onclick={confirmBulkMode}>Confirm {modeName(confirmingBulk.mode)}</button
          >
        </div>
      {/if}
      {#if bulkNotice !== null}<div id="bulk-status" class="notice" role="status" tabindex="-1">
          {bulkNotice}
        </div>{/if}
      {#if mutationErrors.bulk !== undefined}<ErrorNotice error={mutationErrors.bulk} />{/if}
    </section>
  {/if}

  <section class="surface table-card" aria-busy={resource.loading}>
    <div class="section-heading">
      <div>
        <p class="eyebrow">Global tool set</p>
        <h2>{resource.data?.total ?? 0} tools</h2>
      </div>
      {#if resource.loading}<span class="muted-status" role="status">Refreshing...</span>{/if}
    </div>
    {#if resource.data === null && resource.loading}
      <div class="loading-panel" aria-live="polite">Loading tools...</div>
    {:else if resource.data !== null && resource.data.items.length === 0}
      <div class="table-empty">
        <p>No tools match this page or filter set.</p>
        {#if urlState.offset > 0}
          <div class="button-row empty-recovery">
            <a
              class="button-link"
              href={toolsUrl(urlState, { offset: Math.max(0, urlState.offset - 50), tool: null })}
              >Previous page</a
            >
            <a class="button-link" href={toolsUrl(urlState, { offset: 0, tool: null })}
              >First page</a
            >
          </div>
        {/if}
      </div>
    {:else if resource.data !== null}
      <div class="table-scroll">
        <table>
          <caption>Only tools on this page are included in bulk changes.</caption>
          <thead
            ><tr>
              <th scope="col">
                <input
                  bind:this={selectAllInput}
                  aria-label="Select all active tools on this page"
                  type="checkbox"
                  disabled={resource.loading || pending.includes("bulk")}
                  checked={resource.data.items.some((tool) => tool.present) &&
                    resource.data.items
                      .filter((tool) => tool.present)
                      .every((tool) => selected.includes(tool.id))}
                  onchange={(event) => toggleCurrentPage(event.currentTarget.checked)}
                />
              </th>
              <th scope="col">Tool</th><th scope="col">Behavior</th><th scope="col">Details</th>
            </tr></thead
          >
          <tbody>
            {#each resource.data.items as tool (tool.id)}
              {@const inherited = inheritedMode(tool)}
              <tr class:removed-row={!tool.present}>
                <td data-label="Select">
                  <input
                    aria-label={`Select ${tool.displayName}`}
                    type="checkbox"
                    disabled={resource.loading || pending.includes("bulk") || !tool.present}
                    checked={selected.includes(tool.id)}
                    onchange={(event) => toggleSelected(tool.id, event.currentTarget.checked)}
                  />
                </td>
                <td data-label="Tool">
                  <strong>{tool.displayName}</strong>
                  <code>{tool.callablePath}</code>
                  <small>{tool.sourceSlug}{tool.description ? ` · ${tool.description}` : ""}</small>
                  {#if !tool.present}<span class="status-pill revoked">Removed</span>{/if}
                </td>
                <td data-label="Behavior">
                  <fieldset
                    class="mode-control row-modes"
                    disabled={resource.loading || !tool.present || pending.includes(tool.id)}
                  >
                    <legend class="visually-hidden">Behavior for {tool.displayName}</legend>
                    <label
                      title={inherited === null
                        ? "Source default is not available yet"
                        : inheritLabel(inherited)}
                    >
                      <input
                        type="radio"
                        name={`tool-${tool.id}`}
                        checked={tool.modeOverride === null}
                        disabled={inherited === null}
                        onchange={() => changeToolMode(tool, null)}
                      />
                      {inherited === null
                        ? sources.loading
                          ? "Inherit (loading source default)"
                          : "Inherit (source default unavailable)"
                        : inheritLabel(inherited)}
                    </label>
                    {#each toolModes as mode}
                      <label title={modeLabel(mode)}>
                        <input
                          type="radio"
                          name={`tool-${tool.id}`}
                          checked={tool.modeOverride === mode}
                          onchange={() => changeToolMode(tool, mode)}
                        />
                        {modeName(mode)}
                      </label>
                    {/each}
                  </fieldset>
                  <small>{provenanceLabel(tool.effectiveMode.provenance)}</small>
                  {#if mutationErrors[tool.id] !== undefined}<ErrorNotice
                      error={mutationErrors[tool.id]}
                    />{/if}
                </td>
                <td data-label="Details"
                  ><a
                    id={`inspect-tool-${tool.id}`}
                    class="detail-link"
                    href={detailUrl(tool.id)}
                    onclick={() => (detailReturnId = tool.id)}>Inspect</a
                  ></td
                >
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <nav class="pagination" aria-label="Tool pages">
        {#if urlState.offset > 0}
          <a href={toolsUrl(urlState, { offset: Math.max(0, urlState.offset - 50), tool: null })}
            >Newer page</a
          >
        {:else}<span></span>{/if}
        <span
          >{urlState.offset + 1}–{Math.min(
            urlState.offset + resource.data.items.length,
            resource.data.total,
          )} of {resource.data.total}</span
        >
        {#if resource.data.hasMore && resource.data.nextOffset !== null}
          <a href={toolsUrl(urlState, { offset: resource.data.nextOffset, tool: null })}
            >Older page</a
          >
        {/if}
      </nav>
    {/if}
  </section>

  {#if urlState.tool !== null}
    <aside
      id="tool-detail-panel"
      class="surface detail-panel"
      aria-labelledby="tool-detail-title"
      aria-busy={detail.loading}
      tabindex="-1"
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">Tool detail</p>
          <h2 id="tool-detail-title">{detail.data?.displayName ?? "Loading..."}</h2>
        </div>
        <a class="button-link" href={detailUrl(null)}>Close details</a>
      </div>
      {#if detail.error !== null}<div class="detail-body">
          <ErrorNotice error={detail.error} />
          <button type="button" onclick={() => (detailRefreshKey += 1)}>Retry details</button>
        </div>
      {:else if detail.loading && detail.data === null}<div class="loading-panel" role="status">
          Loading tool detail...
        </div>
      {:else if detail.data !== null}
        <div class="detail-body">
          {#if detail.loading}<p class="muted-status" role="status">
              Refreshing tool detail...
            </p>{/if}
          <dl class="detail-list">
            <div>
              <dt>Callable path</dt>
              <dd><code>{detail.data.callablePath}</code></dd>
            </div>
            <div>
              <dt>Sandbox path</dt>
              <dd><code>{detail.data.sandboxPath}</code></dd>
            </div>
            <div>
              <dt>Effective behavior</dt>
              <dd>
                {modeLabel(detail.data.effectiveMode.mode)} · {provenanceLabel(
                  detail.data.effectiveMode.provenance,
                )}
              </dd>
            </div>
          </dl>
          <h3>Input schema</h3>
          <pre>{JSON.stringify(detail.data.inputSchema, null, 2)}</pre>
          {#if detail.data.outputSchema !== null}
            <h3>Output schema</h3>
            <pre>{JSON.stringify(detail.data.outputSchema, null, 2)}</pre>
          {/if}
        </div>
      {/if}
    </aside>
  {/if}
</DashboardShell>
