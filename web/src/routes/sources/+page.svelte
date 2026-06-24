<script lang="ts">
  import { tick, untrack } from "svelte";
  import DashboardShell from "$lib/DashboardShell.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import {
    createOpenApiSource,
    deleteOpenApiCredentials,
    deleteSource,
    getOpenApiCredentials,
    listSources,
    previewOpenApiSource,
    putOpenApiCredentials,
    refreshOpenApiSource,
    setSourceMode,
    type ApiError,
    type OpenApiPreview,
    type OpenApiSpecInput,
    type SourceList,
    type ToolMode,
  } from "$lib/api";
  import {
    beginResourceLoad,
    createLatestRequest,
    emptyResource,
    modeLabel,
    settleResourceLoad,
    toolModes,
    unexpectedRequestError,
  } from "$lib/catalog-state";
  import { useAuthState } from "$lib/auth.svelte";
  import { previewToolKey, requiresBroadConfirmation, sourceModeImpact } from "$lib/catalog-ux";
  import {
    buildCredentialMap,
    duplicateCredentialNames,
    isSupportedCredentialType,
    type CredentialDraft,
    type SupportedCredentialType,
  } from "$lib/openapi-credentials";

  const auth = useAuthState();
  const latest = createLatestRequest();
  const credentialRequest = createLatestRequest();
  let resource = $state(emptyResource<SourceList>());
  let refreshKey = $state(0);
  let pending = $state<string[]>([]);
  let mutationErrors = $state<Record<string, ApiError>>({});
  let conflictNotice = $state<string | null>(null);
  let confirmingDelete = $state<string | null>(null);
  let sourceModeDrafts = $state<Record<string, ToolMode | null>>({});
  let confirmingSourceMode = $state<string | null>(null);
  let locatorType = $state<"url" | "inline">("url");
  let specUrl = $state("");
  let specContent = $state("");
  let allowPrivateNetwork = $state(false);
  let displayName = $state("");
  let displayNameEdited = $state(false);
  let preferredSlug = $state("");
  let sourceDescription = $state("");
  let importCredentialRows = $state<CredentialDraft[]>([]);
  let credentialEditorSource = $state<string | null>(null);
  let confirmingCredentialClear = $state<string | null>(null);
  let credentialRevision = $state<number | null>(null);
  let credentialRows = $state<CredentialDraft[]>([]);
  let credentialBusySource = $state<string | null>(null);
  let credentialFailure = $state<{ sourceId: string; error: ApiError } | null>(null);
  let credentialCleanup: (() => void) | null = null;
  let credentialCounter = 0;
  let currentDuplicateCredentialNames = $derived(duplicateCredentialNames(credentialRows));
  let preview = $state<OpenApiPreview | null>(null);
  let previewFingerprint = $state<string | null>(null);
  let importError = $state<ApiError | null>(null);
  let importNotice = $state<string | null>(null);
  let previewBusy = $state(false);
  let createBusy = $state(false);
  let previewCurrent = $derived(
    preview !== null && previewFingerprint === currentSpecFingerprint(),
  );
  const mutationControllers = new Map<string, AbortController>();

  $effect(() => {
    const requestKey = String(refreshKey);
    resource = beginResourceLoad(untrack(() => resource));
    return latest.start(
      async (signal) => ({ requestKey, result: await listSources(undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== String(refreshKey)) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        resource = settleResourceLoad(resource, result);
      },
      () => {
        resource = settleResourceLoad(resource, {
          ok: false,
          error: unexpectedRequestError(),
        });
      },
    );
  });

  $effect(() => () => {
    for (const controller of mutationControllers.values()) controller.abort();
    credentialCleanup?.();
  });

  async function persistSourceMode(sourceId: string, mode: ToolMode | null, revision: number) {
    const mutationId = sourceMutationId("mode", sourceId);
    clearSourceMutationError(sourceId);
    const controller = beginMutation(mutationId);
    conflictNotice = null;
    const result = await setSourceMode(sourceId, mode, revision, undefined, controller.signal);
    if (!finishMutation(mutationId, controller)) return;
    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      if (result.error.status === 409) {
        conflictNotice =
          "Source defaults changed elsewhere. The latest settings are shown for review.";
        const { [sourceId]: _removed, ...remainingDrafts } = sourceModeDrafts;
        sourceModeDrafts = remainingDrafts;
        confirmingSourceMode = null;
        refreshKey += 1;
        await tick();
        document.getElementById("source-conflict")?.focus();
      } else {
        mutationErrors = { ...mutationErrors, [sourceId]: result.error };
      }
      return;
    }

    const { [sourceId]: _removed, ...remainingDrafts } = sourceModeDrafts;
    sourceModeDrafts = remainingDrafts;
    confirmingSourceMode = null;
    importNotice =
      mode === null
        ? "Source default changed to Tool defaults."
        : `Source default changed to ${modeLabel(mode)}.`;

    const current = resource.data;
    if (current !== null) {
      resource = {
        ...resource,
        data: {
          ...current,
          sources: current.sources.map((source) =>
            source.id === sourceId ? result.value : source,
          ),
        },
      };
    }
    focusSourceStatus();
  }

  async function removeSource(sourceId: string, displayName: string) {
    const mutationId = sourceMutationId("delete", sourceId);
    clearSourceMutationError(sourceId);
    const controller = beginMutation(mutationId);
    const result = await deleteSource(sourceId, undefined, controller.signal);
    if (!finishMutation(mutationId, controller)) return;
    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      mutationErrors = { ...mutationErrors, [sourceId]: result.error };
      return;
    }
    if (credentialEditorSource === sourceId) clearCredentialEditor(false);
    confirmingDelete = null;
    importNotice = `${displayName} was deleted.`;
    refreshKey += 1;
    await tick();
    document.getElementById("source-status")?.focus();
  }

  async function previewSource(event: SubmitEvent) {
    event.preventDefault();
    const spec = currentSpec();
    const fingerprint = currentSpecFingerprint();
    const controller = beginMutation("openapi-preview");
    previewBusy = true;
    importError = null;
    importNotice = null;
    const result = await previewOpenApiSource(
      spec,
      allowPrivateNetwork,
      undefined,
      controller.signal,
    );
    if (!finishMutation("openapi-preview", controller)) return;
    previewBusy = false;
    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      importError = result.error;
      return;
    }
    preview = result.value;
    previewFingerprint = fingerprint;
    importCredentialRows = result.value.securitySchemes.flatMap((scheme) => {
      const type = credentialDraftType(scheme.credentialType);
      return scheme.supported && type !== null ? [credentialRow(scheme.name, type, false)] : [];
    });
    if (!displayNameEdited) displayName = result.value.title;
  }

  async function createSource() {
    if (!previewCurrent || displayName.trim() === "") return;
    const credentials = buildCredentialMap(importCredentialRows);
    if (credentials === null) return;
    const controller = beginMutation("openapi-create");
    createBusy = true;
    importError = null;
    const result = await createOpenApiSource(
      {
        kind: "openapi",
        displayName: displayName.trim(),
        ...(preferredSlug.trim() ? { preferredSlug: preferredSlug.trim() } : {}),
        ...(sourceDescription.trim() ? { description: sourceDescription.trim() } : {}),
        spec: currentSpec(),
        allowPrivateNetwork,
        ...(Object.keys(credentials).length === 0 ? {} : { credential: { schemes: credentials } }),
      },
      undefined,
      controller.signal,
    );
    if (!finishMutation("openapi-create", controller)) return;
    createBusy = false;
    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      importError = result.error;
      return;
    }
    importNotice = `${result.value.displayName} was imported with ${result.value.toolCount} tools.`;
    clearImportForm();
    refreshKey += 1;
  }

  async function refreshSource(sourceId: string) {
    const mutationId = sourceMutationId("refresh", sourceId);
    clearSourceMutationError(sourceId);
    const controller = beginMutation(mutationId);
    const result = await refreshOpenApiSource(sourceId, undefined, controller.signal);
    if (!finishMutation(mutationId, controller)) return;
    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      mutationErrors = { ...mutationErrors, [sourceId]: result.error };
      return;
    }
    importNotice = `Source refreshed: ${result.value.activeToolCount} active tools, ${result.value.tombstonedToolCount} removed.`;
    refreshKey += 1;
  }

  function openCredentialEditor(sourceId: string) {
    if (credentialEditorSource === sourceId) {
      clearCredentialEditor();
      return;
    }
    runCredentialOperation(
      sourceId,
      (signal) => getOpenApiCredentials(sourceId, undefined, signal),
      (result) => {
        if (!result.ok) {
          if (auth.recoverFromApiError(result.error)) return;
          credentialFailure = { sourceId, error: result.error };
          return;
        }
        credentialEditorSource = sourceId;
        confirmingCredentialClear = null;
        credentialRevision = result.value.revision;
        credentialRows = result.value.configuredSchemes.flatMap((scheme) => {
          const type = credentialDraftType(scheme.credentialType);
          return type === null ? [] : [credentialRow(scheme.name, type, true)];
        });
        void tick().then(() => document.getElementById(`credential-editor-${sourceId}`)?.focus());
      },
    );
  }

  function saveCredentials(sourceId: string) {
    if (credentialRevision === null || credentialRows.length === 0) return;
    const credentials = buildCredentialMap(credentialRows);
    if (credentials === null) return;
    const expectedRevision = credentialRevision;
    runCredentialOperation(
      sourceId,
      (signal) => putOpenApiCredentials(sourceId, expectedRevision, credentials, undefined, signal),
      (result) => {
        if (!result.ok) {
          if (auth.recoverFromApiError(result.error)) return;
          if (result.error.status === 409) {
            conflictNotice =
              "Credentials changed elsewhere. Reopen the editor and enter them again.";
            clearCredentialEditor(false);
            void tick().then(() => document.getElementById("source-conflict")?.focus());
          } else {
            credentialFailure = { sourceId, error: result.error };
          }
          return;
        }
        importNotice = "Credentials were replaced. Secret values remain hidden.";
        clearCredentialEditor(false);
        focusSourceStatus();
      },
    );
  }

  function clearCredentials(sourceId: string) {
    if (credentialRevision === null) return;
    const expectedRevision = credentialRevision;
    runCredentialOperation(
      sourceId,
      (signal) => deleteOpenApiCredentials(sourceId, expectedRevision, undefined, signal),
      (result) => {
        if (!result.ok) {
          if (auth.recoverFromApiError(result.error)) return;
          if (result.error.status === 409) {
            conflictNotice =
              "Credentials changed elsewhere. Reopen the editor before clearing them.";
            clearCredentialEditor(false);
            void tick().then(() => document.getElementById("source-conflict")?.focus());
          } else {
            credentialFailure = { sourceId, error: result.error };
          }
          return;
        }
        importNotice = "All credentials for this source were cleared.";
        clearCredentialEditor(false);
        focusSourceStatus();
      },
    );
  }

  function runCredentialOperation<Value>(
    sourceId: string,
    task: (signal: AbortSignal) => Promise<Value>,
    commit: (value: Value) => void,
  ) {
    credentialFailure = null;
    conflictNotice = null;
    importNotice = null;
    credentialBusySource = sourceId;
    credentialCleanup = credentialRequest.start(
      task,
      (value) => {
        credentialBusySource = null;
        credentialCleanup = null;
        credentialFailure = null;
        commit(value);
      },
      () => {
        credentialBusySource = null;
        credentialCleanup = null;
        credentialFailure = { sourceId, error: unexpectedRequestError() };
      },
    );
  }

  function clearCredentialEditor(restoreFocus = true) {
    const sourceId = credentialEditorSource;
    credentialCleanup?.();
    credentialCleanup = null;
    credentialBusySource = null;
    credentialEditorSource = null;
    confirmingCredentialClear = null;
    credentialFailure = null;
    credentialRows = [];
    credentialRevision = null;
    if (restoreFocus && sourceId !== null) {
      void tick().then(() => document.getElementById(`manage-credentials-${sourceId}`)?.focus());
    }
  }

  function focusSourceStatus() {
    void tick().then(() => document.getElementById("source-status")?.focus());
  }

  async function beginDelete(sourceId: string) {
    confirmingDelete = sourceId;
    await tick();
    document.getElementById(`cancel-delete-${sourceId}`)?.focus();
  }

  async function cancelDelete(sourceId: string) {
    confirmingDelete = null;
    await tick();
    document.getElementById(`delete-source-${sourceId}`)?.focus();
  }

  function currentSpec(): OpenApiSpecInput {
    return locatorType === "url"
      ? { type: "url", url: specUrl.trim() }
      : { type: "inline", content: specContent };
  }

  function currentSpecFingerprint() {
    const spec = currentSpec();
    return `${allowPrivateNetwork ? "private" : "public"}:${spec.type}:${spec.type === "url" ? spec.url : spec.content}`;
  }

  function credentialRow(
    name: string,
    credentialType: SupportedCredentialType,
    enabled: boolean,
  ): CredentialDraft {
    credentialCounter += 1;
    return {
      key: `credential-${credentialCounter}`,
      name,
      credentialType,
      enabled,
      value: "",
      username: "",
    };
  }

  function addCredentialRow() {
    credentialRows = [...credentialRows, credentialRow("", "api_key", true)];
  }

  async function removeCredentialRow(key: string, sourceId: string) {
    const index = credentialRows.findIndex((row) => row.key === key);
    const remaining = credentialRows.filter((row) => row.key !== key);
    credentialRows = remaining;
    await tick();
    const target = remaining[Math.min(index, remaining.length - 1)];
    if (target !== undefined) {
      document.getElementById(`credential-name-${target.key}`)?.focus();
    } else {
      document.getElementById(`add-credential-${sourceId}`)?.focus();
    }
  }

  async function beginCredentialClear(sourceId: string) {
    confirmingCredentialClear = sourceId;
    await tick();
    document.getElementById(`cancel-clear-credentials-${sourceId}`)?.focus();
  }

  async function cancelCredentialClear(sourceId: string) {
    confirmingCredentialClear = null;
    await tick();
    document.getElementById(`clear-credentials-${sourceId}`)?.focus();
  }

  function credentialTypeLabel(type: string) {
    if (type === "api_key") return "API key";
    if (type === "bearer") return "Bearer token";
    if (type === "basic") return "Basic auth";
    if (type === "oauth_access_token" || type === "manual_oauth_access_token") {
      return "OAuth access token (manual)";
    }
    return type;
  }

  function credentialDraftType(type: string): SupportedCredentialType | null {
    if (type === "manual_oauth_access_token") return "oauth_access_token";
    return isSupportedCredentialType(type) ? type : null;
  }

  function clearImportForm() {
    locatorType = "url";
    specUrl = "";
    specContent = "";
    allowPrivateNetwork = false;
    displayName = "";
    displayNameEdited = false;
    preferredSlug = "";
    sourceDescription = "";
    importCredentialRows = [];
    preview = null;
    previewFingerprint = null;
    importError = null;
  }

  function authenticatedPreviewWithoutCredentials() {
    if (preview === null || !preview.securitySchemes.some((scheme) => scheme.supported)) {
      return false;
    }
    return importCredentialRows.every((row) => !row.enabled);
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

  function sourceMutationId(operation: "mode" | "refresh" | "delete", sourceId: string) {
    return `${operation}:${sourceId}`;
  }

  function sourceOperationPending(sourceId: string) {
    return (
      resource.loading ||
      (["mode", "refresh", "delete"] as const).some((operation) =>
        pending.includes(sourceMutationId(operation, sourceId)),
      )
    );
  }

  function clearSourceMutationError(sourceId: string) {
    const { [sourceId]: _removed, ...remaining } = mutationErrors;
    mutationErrors = remaining;
  }

  function stagedSourceMode(sourceId: string, current: ToolMode | null) {
    return sourceId in sourceModeDrafts ? sourceModeDrafts[sourceId] : current;
  }

  function stageSourceMode(sourceId: string, mode: ToolMode | null) {
    sourceModeDrafts = { ...sourceModeDrafts, [sourceId]: mode };
    if (confirmingSourceMode === sourceId) confirmingSourceMode = null;
  }

  function applySourceMode(
    sourceId: string,
    current: ToolMode | null,
    revision: number,
    confirmed = false,
  ) {
    const mode = stagedSourceMode(sourceId, current);
    if (mode === current) return;
    if (!confirmed && requiresBroadConfirmation(mode)) {
      confirmingSourceMode = sourceId;
      void tick().then(() => document.getElementById(`cancel-source-mode-${sourceId}`)?.focus());
      return;
    }
    void persistSourceMode(sourceId, mode, revision);
  }

  async function cancelSourceModeConfirmation(sourceId: string) {
    confirmingSourceMode = null;
    await tick();
    document.getElementById(`apply-source-mode-${sourceId}`)?.focus();
  }

  function finishMutation(id: string, controller: AbortController) {
    if (mutationControllers.get(id) !== controller || controller.signal.aborted) return false;
    mutationControllers.delete(id);
    pending = pending.filter((candidate) => candidate !== id);
    return true;
  }

  function formatTime(timestamp: number | null) {
    return timestamp === null
      ? "Not refreshed yet"
      : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
          timestamp * 1000,
        );
  }

  function kindLabel(kind: "openapi" | "graphql" | "mcp_http" | "mcp_stdio") {
    if (kind === "openapi") return "OpenAPI";
    if (kind === "graphql") return "GraphQL";
    if (kind === "mcp_http") return "MCP HTTP";
    return "MCP stdio";
  }
</script>

<DashboardShell
  title="Sources"
  description="Connect MCP servers, OpenAPI services, and GraphQL endpoints."
>
  {#if conflictNotice !== null}
    <div id="source-conflict" class="notice warning" role="status" tabindex="-1">
      {conflictNotice}
    </div>
  {/if}
  {#if importNotice !== null}<div id="source-status" class="notice" role="status" tabindex="-1">
      {importNotice}
    </div>{/if}

  <details class="surface import-panel" open={resource.data?.sources.length === 0}>
    <summary>Connect an OpenAPI source</summary>
    <form class="import-form" onsubmit={previewSource}>
      <fieldset class="mode-control">
        <legend>Specification location</legend>
        <label><input type="radio" name="locator" value="url" bind:group={locatorType} />URL</label>
        <label
          ><input type="radio" name="locator" value="inline" bind:group={locatorType} />Paste
          document</label
        >
      </fieldset>
      {#if locatorType === "url"}
        <label
          >OpenAPI URL<input
            type="url"
            required
            bind:value={specUrl}
            placeholder="https://api.example.com/openapi.json"
          /></label
        >
      {:else}
        <label
          >OpenAPI JSON or YAML<textarea
            required
            rows="10"
            bind:value={specContent}
            placeholder="openapi: 3.1.0"></textarea></label
        >
      {/if}
      <label class="checkbox-label private-network-choice">
        <input
          type="checkbox"
          bind:checked={allowPrivateNetwork}
          aria-describedby="private-network-help"
        />
        Allow private network addresses for this source
      </label>
      <p class="field-help" id="private-network-help">
        Keep this off unless the specification or API intentionally runs on your local network.
      </p>
      <button type="submit" disabled={previewBusy || createBusy}
        >{previewBusy ? "Inspecting..." : "Preview tools"}</button
      >
      <button type="button" disabled={previewBusy || createBusy} onclick={clearImportForm}
        >Reset importer</button
      >
    </form>

    {#if importError !== null}<ErrorNotice error={importError} />{/if}
    {#if preview !== null}
      <form
        class="preview-panel"
        aria-live="polite"
        onsubmit={(event) => {
          event.preventDefault();
          void createSource();
        }}
      >
        <div>
          <p class="eyebrow">Preview</p>
          <h2>{preview.title}</h2>
          <p>{preview.description ?? "No API description provided."}</p>
        </div>
        <strong>{preview.toolCount} tools found</strong>
        {#if !previewCurrent}<p class="notice warning">
            The specification changed. Preview it again before importing.
          </p>{/if}
        <div class="preview-tools">
          {#each preview.tools.slice(0, 8) as tool, index (previewToolKey(tool.preferredName, index))}
            <span
              ><strong>{tool.displayName}</strong><small>{modeLabel(tool.intrinsicMode)}</small
              ></span
            >
          {/each}
          {#if preview.tools.length > 8}<span>+ {preview.tools.length - 8} more</span>{/if}
        </div>
        <div class="import-fields">
          <label
            >Source name<input
              required
              value={displayName}
              oninput={(event) => {
                displayName = event.currentTarget.value;
                displayNameEdited = true;
              }}
            /></label
          >
          <label
            >Slug (optional)<input
              bind:value={preferredSlug}
              placeholder="generated from name"
            /></label
          >
          <label class="wide-field"
            >Description (optional)<input bind:value={sourceDescription} /></label
          >
          {#if preview.securitySchemes.length > 0}
            <fieldset class="credential-schemes wide-field">
              <legend>Authentication schemes</legend>
              <p class="field-help">
                Select every credential you want to configure. Tool requirements use OR between
                groups and AND within a group.
              </p>
              {#each preview.securitySchemes as scheme (scheme.name)}
                {@const row = importCredentialRows.find(
                  (candidate) => candidate.name === scheme.name,
                )}
                <div class="credential-row">
                  <label class="checkbox-label">
                    <input
                      type="checkbox"
                      disabled={row === undefined}
                      checked={row?.enabled ?? false}
                      onchange={(event) => {
                        if (row !== undefined) row.enabled = event.currentTarget.checked;
                      }}
                    />
                    <span
                      ><strong>{scheme.name}</strong><small
                        >{credentialTypeLabel(scheme.credentialType)}{scheme.placement
                          ? ` · ${scheme.placement}`
                          : ""}{scheme.supported ? "" : " · unsupported"}</small
                      ></span
                    >
                  </label>
                  {#if row?.enabled}
                    {#if row.credentialType === "basic"}<label
                        >Username<input
                          required
                          bind:value={row.username}
                          autocomplete="off"
                        /></label
                      >{/if}
                    <label
                      >{credentialTypeLabel(row.credentialType)}<input
                        required
                        type="password"
                        bind:value={row.value}
                        autocomplete="off"
                      /></label
                    >
                  {/if}
                  {#if row?.enabled && row.credentialType === "oauth_access_token"}
                    <p class="field-help wide-field">
                      Supply an access token manually. Executor does not run authorization flows or
                      refresh OAuth tokens yet.
                    </p>
                  {/if}
                </div>
              {/each}
            </fieldset>
          {/if}
        </div>
        <button
          type="submit"
          class="primary"
          disabled={!previewCurrent ||
            previewBusy ||
            createBusy ||
            displayName.trim() === "" ||
            buildCredentialMap(importCredentialRows) === null}
        >
          {createBusy ? "Importing..." : "Import source"}
        </button>
        {#if authenticatedPreviewWithoutCredentials()}
          <p class="notice warning">
            This specification declares authentication, but no credentials are selected. Protected
            tools will fail until credentials are configured.
          </p>
        {/if}
        <p class="field-help">Credentials are encrypted locally and are never shown again.</p>
      </form>
    {/if}
  </details>

  {#if resource.stale && resource.error !== null}
    <div class="stale-notice" role="status">
      Showing the last loaded sources while Executor reconnects.
      <ErrorNotice error={resource.error} />
    </div>
  {:else if resource.error !== null}
    <section class="surface table-unavailable">
      <ErrorNotice error={resource.error} />
      <button type="button" onclick={() => (refreshKey += 1)}>Try again</button>
    </section>
  {/if}

  {#if resource.data === null && resource.loading}
    <section class="surface loading-panel" aria-live="polite">Loading sources...</section>
  {:else if resource.data !== null && resource.data.sources.length === 0}
    <section class="surface empty-state">
      <span class="number-chip">01</span>
      <h2>No sources connected</h2>
      <p>
        This instance has no source data yet. Use the OpenAPI importer above to connect the first
        API.
      </p>
    </section>
  {:else if resource.data !== null}
    <div class="source-grid" aria-busy={resource.loading}>
      {#each resource.data.sources as source (source.id)}
        <article class="surface source-card">
          <header class="source-card-heading">
            <div>
              <p class="eyebrow">{kindLabel(source.kind)} · {source.slug}</p>
              <h2>{source.displayName}</h2>
              {#if source.description !== null}<p>{source.description}</p>{/if}
            </div>
            <span
              class:healthy={source.healthStatus === "healthy"}
              class:error={source.healthStatus === "error"}
              class="health-pill"
            >
              {source.healthStatus}
            </span>
          </header>

          <dl class="source-stats">
            <div>
              <dt>Active tools</dt>
              <dd>{source.toolCount}</dd>
            </div>
            <div>
              <dt>Removed tools</dt>
              <dd>{source.tombstonedToolCount}</dd>
            </div>
            <div>
              <dt>Last refresh</dt>
              <dd>{formatTime(source.lastRefreshedAt)}</dd>
            </div>
          </dl>

          {#if source.healthErrorCode !== null}
            <p class="source-error">Refresh error: <code>{source.healthErrorCode}</code></p>
          {/if}

          <fieldset
            class="mode-control source-mode-control"
            disabled={sourceOperationPending(source.id)}
          >
            <legend>Default tool behavior</legend>
            <label>
              <input
                type="radio"
                name={`source-${source.id}`}
                checked={stagedSourceMode(source.id, source.modeOverride) === null}
                onchange={() => stageSourceMode(source.id, null)}
              />
              Tool defaults
            </label>
            {#each toolModes as mode}
              <label>
                <input
                  type="radio"
                  name={`source-${source.id}`}
                  checked={stagedSourceMode(source.id, source.modeOverride) === mode}
                  onchange={() => stageSourceMode(source.id, mode)}
                />
                {modeLabel(mode)}
              </label>
            {/each}
            <p class="mode-impact">{sourceModeImpact(source.toolCount)}</p>
            <button
              id={`apply-source-mode-${source.id}`}
              type="button"
              disabled={stagedSourceMode(source.id, source.modeOverride) === source.modeOverride}
              onclick={() => applySourceMode(source.id, source.modeOverride, source.revision)}
            >
              {pending.includes(sourceMutationId("mode", source.id))
                ? "Applying..."
                : "Apply source default"}
            </button>
          </fieldset>

          {#if confirmingSourceMode === source.id}
            <div
              class="inline-confirm"
              role="group"
              aria-label={`Confirm default for ${source.displayName}`}
            >
              <strong
                >Confirm {modeLabel(stagedSourceMode(source.id, source.modeOverride) ?? "ask")} as the
                source default?</strong
              >
              <span>{sourceModeImpact(source.toolCount)}</span>
              <button
                id={`cancel-source-mode-${source.id}`}
                type="button"
                disabled={pending.includes(sourceMutationId("mode", source.id))}
                onkeydown={(event) => {
                  if (event.key === "Escape") void cancelSourceModeConfirmation(source.id);
                }}
                onclick={() => cancelSourceModeConfirmation(source.id)}>Cancel</button
              >
              <button
                type="button"
                class:primary={stagedSourceMode(source.id, source.modeOverride) === "enabled"}
                class:danger-button={stagedSourceMode(source.id, source.modeOverride) ===
                  "disabled"}
                disabled={pending.includes(sourceMutationId("mode", source.id))}
                onkeydown={(event) => {
                  if (event.key === "Escape") void cancelSourceModeConfirmation(source.id);
                }}
                onclick={() =>
                  applySourceMode(source.id, source.modeOverride, source.revision, true)}
                >Confirm broad change</button
              >
            </div>
          {/if}

          {#if mutationErrors[source.id] !== undefined}
            <ErrorNotice error={mutationErrors[source.id]} />
          {/if}
          {#if credentialFailure?.sourceId === source.id}
            <ErrorNotice error={credentialFailure.error} />
          {/if}

          <footer class="source-actions">
            <a class="button-link" href={`/tools?source=${encodeURIComponent(source.id)}`}>
              View tools
            </a>
            {#if source.kind === "openapi"}
              <button
                type="button"
                disabled={sourceOperationPending(source.id) || credentialBusySource === source.id}
                onclick={() => refreshSource(source.id)}
              >
                {pending.includes(sourceMutationId("refresh", source.id))
                  ? "Refreshing..."
                  : "Refresh"}
              </button>
              <button
                id={`manage-credentials-${source.id}`}
                type="button"
                disabled={credentialBusySource !== null || sourceOperationPending(source.id)}
                aria-expanded={credentialEditorSource === source.id}
                aria-controls={`credential-editor-${source.id}`}
                onclick={() => openCredentialEditor(source.id)}
              >
                {credentialBusySource === source.id
                  ? "Loading credentials..."
                  : credentialEditorSource === source.id
                    ? "Close credentials"
                    : "Manage credentials"}
              </button>
            {/if}
            {#if confirmingDelete === source.id}
              <div class="inline-confirm" role="group" aria-label={`Delete ${source.displayName}`}>
                <strong>Delete source, compiled tools, and encrypted credentials?</strong>
                <span>Request-log metadata is retained without secret values.</span>
                <button
                  id={`cancel-delete-${source.id}`}
                  type="button"
                  disabled={pending.includes(sourceMutationId("delete", source.id))}
                  onkeydown={(event) => {
                    if (event.key === "Escape") void cancelDelete(source.id);
                  }}
                  onclick={() => cancelDelete(source.id)}>Cancel</button
                >
                <button
                  type="button"
                  class="danger-button"
                  disabled={sourceOperationPending(source.id) || credentialBusySource === source.id}
                  onkeydown={(event) => {
                    if (event.key === "Escape") void cancelDelete(source.id);
                  }}
                  onclick={() => removeSource(source.id, source.displayName)}
                >
                  {pending.includes(sourceMutationId("delete", source.id))
                    ? "Deleting..."
                    : "Delete permanently"}
                </button>
              </div>
            {:else}
              <button
                type="button"
                id={`delete-source-${source.id}`}
                class="danger-link"
                disabled={sourceOperationPending(source.id) || credentialBusySource === source.id}
                onclick={() => beginDelete(source.id)}>Delete</button
              >
            {/if}
          </footer>

          {#if credentialEditorSource === source.id}
            <form
              id={`credential-editor-${source.id}`}
              class="credential-editor"
              tabindex="-1"
              aria-label={`Credentials for ${source.displayName}`}
              aria-live="polite"
              onsubmit={(event) => {
                event.preventDefault();
                void saveCredentials(source.id);
              }}
            >
              <div>
                <h3>Replace credentials</h3>
                <p>Existing values are hidden. Re-enter every credential you want to keep.</p>
              </div>
              {#each credentialRows as row (row.key)}
                <fieldset class="credential-row">
                  <legend>Credential</legend>
                  <label
                    >Security scheme name<input
                      id={`credential-name-${row.key}`}
                      required
                      bind:value={row.name}
                      aria-invalid={duplicateCredentialNames(credentialRows).includes(
                        row.name.trim(),
                      )}
                      aria-describedby={duplicateCredentialNames(credentialRows).includes(
                        row.name.trim(),
                      )
                        ? `credential-errors-${source.id}`
                        : undefined}
                      autocomplete="off"
                    /></label
                  >
                  <label
                    >Type<select bind:value={row.credentialType}
                      ><option value="api_key">API key</option><option value="bearer"
                        >Bearer token</option
                      ><option value="basic">Basic auth</option><option value="oauth_access_token"
                        >OAuth access token</option
                      ></select
                    ></label
                  >
                  {#if row.credentialType === "basic"}<label
                      >Username<input
                        required
                        bind:value={row.username}
                        autocomplete="off"
                      /></label
                    >{/if}
                  <label
                    >{credentialTypeLabel(row.credentialType)}<input
                      required
                      type="password"
                      bind:value={row.value}
                      autocomplete="off"
                    /></label
                  >
                  {#if row.credentialType === "oauth_access_token"}
                    <p class="field-help wide-field">
                      Supply an access token manually. Executor does not run authorization flows or
                      refresh OAuth tokens yet.
                    </p>
                  {/if}
                  <button
                    type="button"
                    class="danger-link"
                    onclick={() => removeCredentialRow(row.key, source.id)}>Remove row</button
                  >
                </fieldset>
              {/each}
              {#if credentialRows.length === 0}<p class="field-help">
                  No credentials are currently configured.
                </p>{/if}
              <div class="button-row">
                <button
                  id={`add-credential-${source.id}`}
                  type="button"
                  disabled={credentialBusySource !== null}
                  onclick={addCredentialRow}>Add credential</button
                >
                <button
                  type="submit"
                  disabled={credentialRows.length === 0 ||
                    credentialBusySource !== null ||
                    currentDuplicateCredentialNames.length > 0}
                  aria-describedby={currentDuplicateCredentialNames.length > 0
                    ? `credential-errors-${source.id}`
                    : undefined}>Save replacement</button
                >
                {#if currentDuplicateCredentialNames.length > 0}<p
                    id={`credential-errors-${source.id}`}
                    class="field-error"
                  >
                    Each security scheme name must be unique. Duplicates: {currentDuplicateCredentialNames.join(
                      ", ",
                    )}.
                  </p>{/if}
                {#if confirmingCredentialClear === source.id}
                  <button
                    id={`cancel-clear-credentials-${source.id}`}
                    type="button"
                    disabled={credentialBusySource !== null}
                    onkeydown={(event) => {
                      if (event.key === "Escape") void cancelCredentialClear(source.id);
                    }}
                    onclick={() => cancelCredentialClear(source.id)}>Cancel clear</button
                  >
                  <button
                    type="button"
                    class="danger-button"
                    disabled={credentialBusySource !== null}
                    onkeydown={(event) => {
                      if (event.key === "Escape") void cancelCredentialClear(source.id);
                    }}
                    onclick={() => clearCredentials(source.id)}>Confirm clear all</button
                  >
                {:else}
                  <button
                    id={`clear-credentials-${source.id}`}
                    type="button"
                    class="danger-link"
                    onclick={() => beginCredentialClear(source.id)}>Clear all credentials</button
                  >
                {/if}
              </div>
            </form>
          {/if}
        </article>
      {/each}
    </div>
  {/if}
</DashboardShell>
