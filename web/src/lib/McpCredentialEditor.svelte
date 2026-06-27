<script lang="ts">
  import { tick, untrack } from "svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import {
    getSourceCredentials,
    listMcpStdioTemplates,
    putMcpHttpCredentials,
    putMcpStdioCredentials,
    type ApiError,
    type Source,
  } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import { createLatestRequest, unexpectedRequestError } from "$lib/catalog-state";
  import {
    buildMcpHttpCredential,
    safeMcpSourceDetails,
    templateSecretFields,
    validateTemplateCatalog,
    validateTemplateDraft,
    type McpHttpAuthDraft,
    type McpTemplateField,
  } from "$lib/mcp-source-state";

  let {
    source,
    disabled = false,
    onbusychange,
    onmutationchange,
  }: {
    source: Source;
    disabled?: boolean;
    onbusychange?: (busy: boolean) => void;
    onmutationchange?: (busy: boolean) => void;
  } = $props();

  const auth = useAuthState();
  const latest = createLatestRequest();
  let open = $state(false);
  let loading = $state(false);
  let saving = $state(false);
  let revision = $state<number | null>(null);
  let error = $state<ApiError | null>(null);
  let notice = $state<string | null>(null);
  let httpDraft = $state<McpHttpAuthDraft>({
    type: "none",
    headerName: "",
    username: "",
    secret: "",
  });
  let stdioFields = $state<readonly McpTemplateField[]>([]);
  let stdioSecrets = $state<Record<string, string>>({});
  let cleanupLoad: (() => void) | null = null;
  let saveController: AbortController | null = null;
  let lifetime = 0;
  let reportedBusy = false;
  let reportedMutation = false;
  let httpCredential = $derived(buildMcpHttpCredential(httpDraft));
  let stdioCredential = $derived(validateTemplateDraft(stdioFields, stdioSecrets));

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      cleanupLoad?.();
      saveController?.abort();
      if (reportedBusy) onbusychange?.(false);
      if (reportedMutation) onmutationchange?.(false);
    };
  });

  $effect(() => {
    const busy = loading || saving;
    if (busy === reportedBusy) return;
    reportedBusy = busy;
    onbusychange?.(busy);
  });

  $effect(() => {
    if (saving === reportedMutation) return;
    reportedMutation = saving;
    onmutationchange?.(saving);
  });

  $effect(() => {
    const isDisabled = disabled;
    untrack(() => {
      if (!isDisabled) {
        if (open && revision === null && !loading && error === null) loadEditor();
        return;
      }

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
        clearSecretDrafts();
      }
    });
  });

  function toggle() {
    if (disabled) return;
    if (open) {
      closeEditor();
      return;
    }
    open = true;
    notice = null;
    loadEditor();
  }

  function loadEditor() {
    if (disabled) return;
    loading = true;
    error = null;
    revision = null;
    stdioFields = [];
    stdioSecrets = {};
    cleanupLoad = latest.start(
      async (signal) => {
        const credentials = await getSourceCredentials(source.id, undefined, signal);
        const templates =
          source.kind === "mcp_stdio"
            ? await listMcpStdioTemplates(undefined, signal)
            : ({ ok: true, value: { templates: [] } } as const);
        return { credentials, templates };
      },
      ({ credentials, templates }) => {
        cleanupLoad = null;
        loading = false;
        if (!credentials.ok) {
          if (!auth?.recoverFromApiError(credentials.error)) error = credentials.error;
          return;
        }
        if (!templates.ok) {
          if (!auth?.recoverFromApiError(templates.error)) error = templates.error;
          return;
        }
        if (source.kind === "mcp_http") {
          const configured = credentials.value.configuredSchemes[0]?.credentialType;
          const type =
            configured === "header"
              ? "api_key_header"
              : configured === "bearer" ||
                  configured === "basic" ||
                  configured === "api_key_header" ||
                  configured === "oauth_access_token"
                ? configured
                : "none";
          httpDraft = {
            type,
            headerName: "",
            username: "",
            secret: "",
          };
          revision = credentials.value.revision;
          return;
        }

        const validated = validateTemplateCatalog(templates.value.templates);
        const templateName = safeMcpSourceDetails("mcp_stdio", source.configuration).templateName;
        const template = validated?.find((candidate) => candidate.name === templateName);
        if (template === undefined) {
          error = unexpectedRequestError();
          return;
        }
        stdioFields = templateSecretFields(template);
        stdioSecrets = {};
        revision = credentials.value.revision;
      },
      () => {
        cleanupLoad = null;
        loading = false;
        error = unexpectedRequestError();
      },
    );
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    const expectedRevision = revision;
    const currentHttpCredential = httpCredential;
    const currentStdioCredential = stdioCredential;
    if (disabled || saving || expectedRevision === null) return;
    if (source.kind !== "mcp_http" && source.kind !== "mcp_stdio") return;
    if (source.kind === "mcp_http" && currentHttpCredential === null) return;
    if (source.kind === "mcp_stdio" && currentStdioCredential === null) return;

    saveController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    saveController = controller;
    saving = true;
    error = null;
    notice = null;
    let operation;
    if (source.kind === "mcp_http") {
      if (currentHttpCredential === null) return;
      operation = putMcpHttpCredentials(
        source.id,
        expectedRevision,
        currentHttpCredential,
        undefined,
        controller.signal,
      );
    } else {
      if (currentStdioCredential === null) return;
      operation = putMcpStdioCredentials(
        source.id,
        expectedRevision,
        { secretValues: currentStdioCredential },
        undefined,
        controller.signal,
      );
    }
    const settled = await operation.then(
      (result) => ({ ok: true, result }) as const,
      () => ({ ok: false }) as const,
    );
    if (owner !== lifetime || saveController !== controller || controller.signal.aborted) return;
    saveController = null;
    saving = false;
    clearSecretDrafts();

    if (!settled.ok) {
      error = unexpectedRequestError();
      await focusEditorError();
      return;
    }
    if (!settled.result.ok) {
      if (auth?.recoverFromApiError(settled.result.error)) return;
      if (settled.result.error.status === 409) {
        revision = null;
        error = settled.result.error;
        await focusEditorError();
        return;
      }
      error = settled.result.error;
      await focusEditorError();
      return;
    }

    revision = settled.result.value.revision;
    open = false;
    notice = "Credentials replaced. Secret values remain hidden.";
    await tick();
    document.getElementById(`mcp-credential-status-${source.id}`)?.focus();
  }

  function clearSecretDrafts() {
    httpDraft = { ...httpDraft, headerName: "", username: "", secret: "" };
    stdioSecrets = {};
  }

  function closeEditor() {
    cleanupLoad?.();
    cleanupLoad = null;
    saveController?.abort();
    saveController = null;
    open = false;
    loading = false;
    saving = false;
    error = null;
    revision = null;
    stdioFields = [];
    clearSecretDrafts();
    void tick().then(() => document.getElementById(`mcp-credentials-${source.id}`)?.focus());
  }

  async function focusEditorError() {
    await tick();
    document.getElementById(`mcp-credential-error-${source.id}`)?.focus();
  }
</script>

<button
  id={`mcp-credentials-${source.id}`}
  type="button"
  {disabled}
  aria-expanded={open}
  aria-controls={`mcp-credential-editor-${source.id}`}
  onclick={toggle}
>
  {open ? "Close credentials" : "Manage credentials"}
</button>

{#if notice !== null}
  <p id={`mcp-credential-status-${source.id}`} class="notice" role="status" tabindex="-1">
    {notice}
  </p>
{/if}

{#if open}
  <form
    id={`mcp-credential-editor-${source.id}`}
    class="credential-editor"
    aria-label={`Credentials for ${source.displayName}`}
    onsubmit={save}
  >
    <div>
      <h3>Replace credentials</h3>
      <p>Existing values are hidden. Saving replaces the complete credential set.</p>
    </div>

    {#if loading}
      <p aria-live="polite">Loading credential metadata...</p>
    {:else if revision !== null && source.kind === "mcp_http"}
      <fieldset disabled={saving || disabled}>
        <legend>HTTP authentication</legend>
        <label>
          Method
          <select
            bind:value={httpDraft.type}
            onchange={() =>
              (httpDraft = { ...httpDraft, headerName: "", username: "", secret: "" })}
          >
            <option value="none">None</option>
            <option value="bearer">Bearer token</option>
            <option value="basic">Basic auth</option>
            <option value="api_key_header">API key header</option>
            <option value="oauth_access_token">OAuth access token (manual, advanced)</option>
          </select>
        </label>
        {#if httpDraft.type === "api_key_header"}
          <label>
            Header name
            <input required autocomplete="off" bind:value={httpDraft.headerName} />
          </label>
        {/if}
        {#if httpDraft.type === "basic"}
          <label>
            Username
            <input required autocomplete="off" bind:value={httpDraft.username} />
          </label>
        {/if}
        {#if httpDraft.type !== "none"}
          <label>
            {httpDraft.type === "bearer"
              ? "Bearer token"
              : httpDraft.type === "basic"
                ? "Password"
                : httpDraft.type === "oauth_access_token"
                  ? "OAuth access token"
                  : "Header value"}
            <input type="password" required autocomplete="off" bind:value={httpDraft.secret} />
          </label>
        {/if}
      </fieldset>
    {:else if revision !== null && source.kind === "mcp_stdio"}
      <fieldset disabled={saving || disabled}>
        <legend>Template secrets</legend>
        {#each stdioFields as field (field.key)}
          <label>
            {field.label}
            <input
              type="password"
              required
              autocomplete="off"
              aria-label={field.label}
              value={stdioSecrets[field.key] ?? ""}
              oninput={(event) => {
                stdioSecrets = { ...stdioSecrets, [field.key]: event.currentTarget.value };
              }}
            />
          </label>
        {/each}
      </fieldset>
    {/if}

    {#if error !== null}
      <div id={`mcp-credential-error-${source.id}`} tabindex="-1"><ErrorNotice {error} /></div>
    {/if}
    <div class="button-row">
      <button type="button" disabled={saving || disabled} onclick={closeEditor}>Cancel</button>
      <button
        type="submit"
        class="primary"
        disabled={loading ||
          saving ||
          disabled ||
          revision === null ||
          (source.kind === "mcp_http" ? httpCredential === null : stdioCredential === null)}
      >
        {saving ? "Saving..." : "Save replacement"}
      </button>
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
</style>
