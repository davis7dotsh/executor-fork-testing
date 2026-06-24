<script lang="ts">
  import { tick } from "svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import type { ApiError, ApiResult, OpenApiCredentialMetadata, Source } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import { createLatestRequest, unexpectedRequestError } from "$lib/catalog-state";
  import {
    buildGraphqlCredential,
    clearGraphqlSecret,
    emptyGraphqlAuthDraft,
    graphqlDraftFromCredentialType,
    type GraphqlAuthDraft,
    type GraphqlCredential,
  } from "$lib/graphql-source-state";

  let {
    source,
    load,
    save,
    onbusychange,
    disabled = false,
  }: {
    source: Source;
    load: (sourceId: string, signal: AbortSignal) => Promise<ApiResult<OpenApiCredentialMetadata>>;
    save: (
      sourceId: string,
      expectedRevision: number,
      credential: GraphqlCredential,
      signal: AbortSignal,
    ) => Promise<ApiResult<OpenApiCredentialMetadata>>;
    onbusychange?: (busy: boolean) => void;
    disabled?: boolean;
  } = $props();

  const auth = useAuthState();
  const latest = createLatestRequest();
  let open = $state(false);
  let loading = $state(false);
  let saving = $state(false);
  let confirmingClear = $state(false);
  let revision = $state<number | null>(null);
  let error = $state<ApiError | null>(null);
  let notice = $state<string | null>(null);
  let draft = $state<GraphqlAuthDraft>(emptyGraphqlAuthDraft());
  let credential = $derived(buildGraphqlCredential(draft));
  let cleanupLoad: (() => void) | null = null;
  let saveController: AbortController | null = null;
  let lifetime = 0;
  let observedSourceId: string | null = null;
  let reportedBusy = false;

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      cleanupLoad?.();
      saveController?.abort();
      draft = clearGraphqlSecret(draft);
      if (reportedBusy) onbusychange?.(false);
    };
  });

  $effect(() => {
    const busy = loading || saving;
    if (busy === reportedBusy) return;
    reportedBusy = busy;
    onbusychange?.(busy);
  });

  $effect(() => {
    if (!disabled) {
      if (open && revision === null && !loading && error === null) loadEditor(source.id);
      return;
    }

    confirmingClear = false;
    if (cleanupLoad !== null) {
      cleanupLoad();
      cleanupLoad = null;
      loading = false;
      revision = null;
      error = null;
    }
    if (saveController !== null) {
      saveController.abort();
      saveController = null;
      saving = false;
      revision = null;
      error = null;
      draft = clearGraphqlSecret(draft);
    }
  });

  $effect(() => {
    const sourceId = source.id;
    if (observedSourceId === null) {
      observedSourceId = sourceId;
      return;
    }
    if (observedSourceId === sourceId) return;

    observedSourceId = sourceId;
    const shouldReload = open;
    resetEditorState();
    notice = null;
    open = shouldReload;
    if (shouldReload) loadEditor(sourceId);
  });

  function toggle() {
    if (open) {
      closeEditor();
      return;
    }
    open = true;
    notice = null;
    loadEditor(source.id);
  }

  function loadEditor(sourceId: string) {
    loading = true;
    error = null;
    revision = null;
    confirmingClear = false;
    draft = emptyGraphqlAuthDraft();
    cleanupLoad = latest.start(
      (signal) => load(sourceId, signal),
      (result) => {
        cleanupLoad = null;
        loading = false;
        if (!result.ok) {
          if (!auth?.recoverFromApiError(result.error)) error = result.error;
          return;
        }
        draft = graphqlDraftFromCredentialType(result.value.configuredSchemes[0]?.credentialType);
        revision = result.value.revision;
      },
      () => {
        cleanupLoad = null;
        loading = false;
        error = unexpectedRequestError();
      },
    );
  }

  function changeAuthType() {
    draft = { ...draft, headerName: "", username: "", secret: "" };
    confirmingClear = false;
  }

  async function saveReplacement(event: SubmitEvent) {
    event.preventDefault();
    const currentCredential = credential;
    if (currentCredential === null || currentCredential === undefined) return;
    await persist(currentCredential, "Credentials replaced. Secret values remain hidden.");
  }

  async function clearCredentials() {
    await persist(null, "Credentials cleared for this source.");
  }

  async function persist(nextCredential: GraphqlCredential, successNotice: string) {
    const expectedRevision = revision;
    if (disabled || saving || expectedRevision === null) return;
    const sourceId = source.id;

    saveController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    saveController = controller;
    saving = true;
    error = null;
    notice = null;
    draft = clearGraphqlSecret(draft);
    const settled = await save(sourceId, expectedRevision, nextCredential, controller.signal).then(
      (result) => ({ ok: true, result }) as const,
      () => ({ ok: false }) as const,
    );
    if (owner !== lifetime || saveController !== controller || controller.signal.aborted) return;
    saveController = null;
    saving = false;

    if (!settled.ok) {
      error = unexpectedRequestError();
      await focusEditorError();
      return;
    }
    if (!settled.result.ok) {
      if (auth?.recoverFromApiError(settled.result.error)) return;
      if (settled.result.error.status === 409) revision = null;
      confirmingClear = false;
      error = settled.result.error;
      await focusEditorError();
      return;
    }

    revision = settled.result.value.revision;
    open = false;
    confirmingClear = false;
    notice = successNotice;
    await tick();
    document.getElementById(`graphql-credential-status-${source.id}`)?.focus();
  }

  function beginClear() {
    if (disabled) return;
    draft = clearGraphqlSecret(draft);
    confirmingClear = true;
    void tick().then(() => document.getElementById(`graphql-cancel-clear-${source.id}`)?.focus());
  }

  function cancelClear() {
    confirmingClear = false;
    void tick().then(() =>
      document.getElementById(`graphql-clear-credentials-${source.id}`)?.focus(),
    );
  }

  function closeEditor() {
    resetEditorState();
    void tick().then(() => document.getElementById(`graphql-credentials-${source.id}`)?.focus());
  }

  function resetEditorState() {
    cleanupLoad?.();
    cleanupLoad = null;
    saveController?.abort();
    saveController = null;
    open = false;
    loading = false;
    saving = false;
    confirmingClear = false;
    error = null;
    revision = null;
    draft = emptyGraphqlAuthDraft();
  }

  async function focusEditorError() {
    await tick();
    document.getElementById(`graphql-credential-error-${source.id}`)?.focus();
  }
</script>

<button
  id={`graphql-credentials-${source.id}`}
  type="button"
  {disabled}
  aria-expanded={open}
  aria-controls={`graphql-credential-editor-${source.id}`}
  onclick={toggle}
>
  {open ? "Close credentials" : "Manage credentials"}
</button>

{#if notice !== null}
  <p id={`graphql-credential-status-${source.id}`} class="notice" role="status" tabindex="-1">
    {notice}
  </p>
{/if}

{#if open}
  <form
    id={`graphql-credential-editor-${source.id}`}
    class="credential-editor"
    aria-label={`Credentials for ${source.displayName}`}
    onsubmit={saveReplacement}
  >
    <div>
      <h3>Replace credentials</h3>
      <p>Existing values are hidden. Saving replaces the complete credential set.</p>
    </div>

    {#if loading}
      <p aria-live="polite">Loading credential metadata...</p>
    {:else if revision !== null}
      <fieldset disabled={disabled || saving}>
        <legend>GraphQL authentication</legend>
        <label>
          Method
          <select bind:value={draft.type} onchange={changeAuthType}>
            <option value="none">None</option>
            <option value="bearer">Bearer token</option>
            <option value="basic">Basic auth</option>
            <option value="api_key_header">API key header</option>
            <option value="oauth_access_token">OAuth access token (manual, advanced)</option>
          </select>
        </label>
        {#if draft.type === "api_key_header"}
          <label>
            Header name
            <input required autocomplete="off" bind:value={draft.headerName} />
          </label>
        {/if}
        {#if draft.type === "basic"}
          <label>
            Username
            <input required autocomplete="off" bind:value={draft.username} />
          </label>
        {/if}
        {#if draft.type !== "none"}
          <label>
            {draft.type === "bearer"
              ? "Bearer token"
              : draft.type === "basic"
                ? "Password"
                : draft.type === "oauth_access_token"
                  ? "OAuth access token"
                  : "Header value"}
            <input type="password" required autocomplete="off" bind:value={draft.secret} />
          </label>
        {/if}
      </fieldset>
    {/if}

    {#if error !== null}
      <div id={`graphql-credential-error-${source.id}`} tabindex="-1"><ErrorNotice {error} /></div>
    {/if}
    <div class="button-row">
      <button type="button" disabled={saving} onclick={closeEditor}>Cancel</button>
      <button
        type="submit"
        class="primary"
        disabled={disabled ||
          loading ||
          saving ||
          revision === null ||
          credential === null ||
          credential === undefined}
      >
        {saving ? "Saving..." : "Save replacement"}
      </button>
      {#if confirmingClear}
        <span
          class="confirmation-actions"
          role="group"
          aria-label={`Confirm clearing credentials for ${source.displayName}`}
        >
          <button
            id={`graphql-cancel-clear-${source.id}`}
            type="button"
            disabled={disabled || saving}
            onkeydown={(event) => {
              if (event.key === "Escape") cancelClear();
            }}
            onclick={cancelClear}>Cancel clear</button
          >
          <button
            type="button"
            class="danger-button"
            disabled={disabled || saving || revision === null}
            onkeydown={(event) => {
              if (event.key === "Escape") cancelClear();
            }}
            onclick={clearCredentials}>Confirm clear</button
          >
        </span>
      {:else}
        <button
          id={`graphql-clear-credentials-${source.id}`}
          type="button"
          class="danger-link"
          disabled={disabled || loading || saving || revision === null}
          onclick={beginClear}>Clear credentials</button
        >
      {/if}
    </div>
  </form>
{/if}

<style>
  .credential-editor,
  fieldset {
    display: grid;
    gap: 0.85rem;
  }

  .credential-editor {
    flex-basis: 100%;
    width: 100%;
    border-top: 1px solid #293247;
    padding-top: 1rem;
  }

  .credential-editor h3,
  .credential-editor p {
    margin: 0;
  }

  .credential-editor > div:first-child p {
    margin-top: 0.3rem;
    color: #9da8bb;
    font-size: 0.78rem;
  }

  fieldset {
    min-width: 0;
    margin: 0;
    border: 1px solid #293247;
    border-radius: 10px;
    padding: 0.85rem;
    background: #0d131d;
  }

  legend {
    padding: 0 0.35rem;
    color: #aeb8ca;
    font-size: 0.72rem;
    font-weight: 750;
  }

  .confirmation-actions {
    display: contents;
  }
</style>
