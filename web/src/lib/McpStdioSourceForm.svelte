<script lang="ts">
  import { tick, untrack } from "svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import {
    createMcpStdioSource,
    listMcpStdioTemplates,
    type ApiError,
    type McpStdioTemplate,
    type Source,
  } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import {
    beginResourceLoad,
    createLatestRequest,
    emptyResource,
    settleResourceLoad,
    unexpectedRequestError,
  } from "$lib/catalog-state";
  import {
    reconcileTemplateSelection,
    templateDescriptorFingerprint,
    templateSecretFields,
    validateTemplateCatalog,
    validateTemplateDraft,
  } from "$lib/mcp-source-state";

  let { oncreated }: { oncreated: (source: Source) => void } = $props();

  const auth = useAuthState();
  const latestTemplates = createLatestRequest();
  let templates = $state(emptyResource<readonly McpStdioTemplate[]>());
  let refreshKey = $state(0);
  let selectedTemplate = $state<string | null>(null);
  let displayName = $state("");
  let description = $state("");
  let secretValues = $state<Record<string, string>>({});
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let activeController: AbortController | null = null;
  let lifetime = 0;
  let currentTemplate = $derived(
    templates.data?.find((template) => template.name === selectedTemplate) ?? null,
  );
  let currentFields = $derived(
    currentTemplate === null ? [] : templateSecretFields(currentTemplate),
  );
  let validatedSecrets = $derived(validateTemplateDraft(currentFields, secretValues));

  $effect(() => {
    const requestKey = String(refreshKey);
    templates = beginResourceLoad(untrack(() => templates));
    return latestTemplates.start(
      async (signal) => ({ requestKey, result: await listMcpStdioTemplates(undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== String(refreshKey)) return;
        if (!result.ok) {
          if (!auth?.recoverFromApiError(result.error)) {
            templates = settleResourceLoad(templates, result);
          }
          return;
        }
        const validated = validateTemplateCatalog(result.value.templates);
        if (validated === null) {
          templates = settleResourceLoad(templates, {
            ok: false,
            error: unexpectedRequestError(),
          });
          return;
        }
        const previousDescriptor = templates.data?.find(
          (template) => template.name === selectedTemplate,
        );
        templates = settleResourceLoad(templates, { ok: true, value: validated });
        const nextSelection = reconcileTemplateSelection(selectedTemplate, validated);
        if (nextSelection !== selectedTemplate) selectTemplate(nextSelection);
        else {
          const nextDescriptor = validated.find((template) => template.name === nextSelection);
          if (
            templateDescriptorFingerprint(previousDescriptor) !==
            templateDescriptorFingerprint(nextDescriptor)
          ) {
            secretValues = {};
          }
        }
      },
      () => {
        templates = settleResourceLoad(templates, {
          ok: false,
          error: unexpectedRequestError(),
        });
      },
    );
  });

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      activeController?.abort();
      activeController = null;
    };
  });

  function selectTemplate(name: string | null) {
    if (name === selectedTemplate) return;
    selectedTemplate = name;
    secretValues = {};
    error = null;
  }

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    const templateName = selectedTemplate;
    const secrets = validatedSecrets;
    if (busy || templateName === null || secrets === null) return;

    activeController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    activeController = controller;
    busy = true;
    error = null;
    const settled = await createMcpStdioSource(
      {
        kind: "mcp_stdio",
        displayName: displayName.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        templateName,
        secretValues: secrets,
      },
      undefined,
      controller.signal,
    ).then(
      (result) => ({ ok: true, result }) as const,
      () => ({ ok: false }) as const,
    );
    if (owner !== lifetime || activeController !== controller || controller.signal.aborted) return;
    activeController = null;
    busy = false;

    if (!settled.ok) {
      secretValues = {};
      error = unexpectedRequestError();
      await focusError();
      return;
    }
    if (!settled.result.ok) {
      secretValues = {};
      if (!auth?.recoverFromApiError(settled.result.error)) {
        error = settled.result.error;
        await focusError();
      }
      return;
    }

    const source = settled.result.value;
    displayName = "";
    description = "";
    secretValues = {};
    oncreated(source);
  }

  async function focusError() {
    await tick();
    document.getElementById("mcp-stdio-error")?.focus();
  }
</script>

<section class="mcp-form" aria-labelledby="mcp-stdio-form-title">
  <div>
    <h2 id="mcp-stdio-form-title">Trusted local MCP template</h2>
    <p>
      Choose a template configured on this machine. Browser users cannot enter commands, arguments,
      working directories, or environment variable names.
    </p>
  </div>
  {#if templates.data !== null && templates.data.length > 0 && !templates.stale}
    <button type="button" disabled={templates.loading} onclick={() => (refreshKey += 1)}>
      {templates.loading ? "Refreshing templates..." : "Refresh templates"}
    </button>
  {/if}

  {#if templates.stale && templates.error !== null}
    <div class="notice warning" role="status">
      Showing the last loaded template list while Executor reconnects.
      <ErrorNotice error={templates.error} />
      <button type="button" disabled={templates.loading} onclick={() => (refreshKey += 1)}>
        {templates.loading ? "Retrying..." : "Try again"}
      </button>
    </div>
  {:else if templates.error !== null}
    <div class="table-unavailable">
      <ErrorNotice error={templates.error} />
      <button type="button" onclick={() => (refreshKey += 1)}>Try again</button>
    </div>
  {/if}

  {#if templates.data === null && templates.loading}
    <p aria-live="polite">Loading trusted templates...</p>
  {:else if templates.data?.length === 0}
    <div class="notice">
      <strong>No trusted local templates are configured.</strong>
      <small>
        Add templates to the machine-admin JSON registry selected by
        <code>--mcp-stdio-templates</code> or <code>EXECUTOR_MCP_STDIO_TEMPLATES_FILE</code>,
        restart Executor, then try again.
      </small>
    </div>
    <button type="button" disabled={templates.loading} onclick={() => (refreshKey += 1)}>
      {templates.loading ? "Refreshing..." : "Refresh templates"}
    </button>
  {:else if templates.data !== null}
    <form onsubmit={connect}>
      <fieldset disabled={busy || templates.loading || templates.stale}>
        <legend>Local process source</legend>
        <label>
          Trusted template
          <select
            value={selectedTemplate ?? ""}
            onchange={(event) => selectTemplate(event.currentTarget.value || null)}
          >
            {#each templates.data as template (template.name)}
              <option value={template.name}>{template.name}</option>
            {/each}
          </select>
        </label>
        <label>
          Source name
          <input required maxlength="120" bind:value={displayName} placeholder="Local tools" />
        </label>
        <label>
          Description (optional)
          <input maxlength="500" bind:value={description} />
        </label>
        {#each currentFields as field (field.key)}
          <label>
            {field.label}
            <input
              type="password"
              required
              autocomplete="off"
              aria-label={field.label}
              value={secretValues[field.key] ?? ""}
              oninput={(event) => {
                secretValues = { ...secretValues, [field.key]: event.currentTarget.value };
              }}
            />
            <small>{field.description} It is encrypted locally and never shown again.</small>
          </label>
        {/each}
      </fieldset>

      {#if error !== null}
        <div id="mcp-stdio-error" tabindex="-1"><ErrorNotice {error} /></div>
      {/if}
      <button
        class="primary"
        type="submit"
        disabled={busy ||
          templates.loading ||
          templates.stale ||
          selectedTemplate === null ||
          validatedSecrets === null}
      >
        {busy ? "Connecting..." : "Connect source"}
      </button>
    </form>
  {/if}
</section>

<style>
  .mcp-form,
  form,
  fieldset {
    display: grid;
    gap: 1rem;
  }

  .mcp-form {
    padding: 1.3rem;
  }

  .mcp-form h2,
  .mcp-form p {
    margin: 0;
  }

  .mcp-form > div:first-child p {
    margin-top: 0.35rem;
    color: #a8b2c4;
    line-height: 1.55;
  }

  fieldset {
    min-width: 0;
    margin: 0;
    border: 0;
    padding: 0;
  }

  legend {
    color: #edf0f6;
    font-size: 1.05rem;
    font-weight: 750;
  }
</style>
