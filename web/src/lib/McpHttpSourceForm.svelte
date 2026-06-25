<script lang="ts">
  import { tick } from "svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { type ApiError, type ApiResult, type McpHttpSourceInput, type Source } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import { unexpectedRequestError } from "$lib/catalog-state";
  import {
    buildMcpHttpCredential,
    requiresPrivateNetworkOptIn,
    type McpHttpAuthDraft,
  } from "$lib/mcp-source-state";
  let {
    create,
    oncreated,
    onbusychange,
    disabled = false,
  }: {
    create: (input: McpHttpSourceInput, signal: AbortSignal) => Promise<ApiResult<Source>>;
    oncreated?: (source: Source) => void;
    onbusychange?: (busy: boolean) => void;
    disabled?: boolean;
  } = $props();

  const auth = useAuthState();
  let endpoint = $state("");
  let displayName = $state("");
  let description = $state("");
  let allowPrivateNetwork = $state(false);
  let credentialDraft = $state<McpHttpAuthDraft>({
    type: "none",
    headerName: "",
    username: "",
    secret: "",
  });
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let localOptInMissing = $derived(
    endpoint.trim() !== "" && requiresPrivateNetworkOptIn(endpoint) && !allowPrivateNetwork,
  );
  let credentialPayload = $derived(buildMcpHttpCredential(credentialDraft));
  let activeController: AbortController | null = null;
  let lifetime = 0;
  let reportedBusy = false;

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      activeController?.abort();
      activeController = null;
      credentialDraft = { ...credentialDraft, secret: "" };
      if (reportedBusy) onbusychange?.(false);
    };
  });

  $effect(() => {
    if (busy === reportedBusy) return;
    reportedBusy = busy;
    onbusychange?.(busy);
  });

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    const currentCredential = credentialPayload;
    if (busy || disabled || localOptInMissing || currentCredential === null) return;

    activeController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    activeController = controller;
    busy = true;
    error = null;
    const input = {
      kind: "mcp_http",
      displayName: displayName.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
      endpoint: endpoint.trim(),
      allowPrivateNetwork,
      ...(currentCredential.credential === null
        ? {}
        : { credential: currentCredential.credential }),
    } satisfies McpHttpSourceInput;
    credentialDraft = { ...credentialDraft, secret: "" };
    const result = await create(input, controller.signal).then(
      (response) => response,
      () => ({ ok: false, error: unexpectedRequestError() }) as const,
    );
    if (owner !== lifetime || activeController !== controller || controller.signal.aborted) return;

    activeController = null;
    busy = false;

    if (!result.ok) {
      if (!auth?.recoverFromApiError(result.error)) {
        error = result.error;
        await focusError();
      }
      return;
    }

    const source = result.value;
    endpoint = "";
    displayName = "";
    description = "";
    allowPrivateNetwork = false;
    credentialDraft = { type: "none", headerName: "", username: "", secret: "" };
    oncreated?.(source);
  }

  async function focusError() {
    await tick();
    document.getElementById("mcp-http-error")?.focus();
  }
</script>

<form class="mcp-form" onsubmit={connect} aria-labelledby="mcp-http-form-title">
  <fieldset disabled={busy || disabled}>
    <legend id="mcp-http-form-title">MCP Streamable HTTP</legend>
    <p>
      Connect a remote or local MCP server. Executor negotiates the protocol and imports its tool
      catalog.
    </p>
    <label>
      Endpoint
      <input
        type="url"
        required
        bind:value={endpoint}
        placeholder="https://mcp.example.com/mcp"
        aria-describedby="mcp-http-connection-policy"
      />
    </label>
    <label>
      Source name
      <input required maxlength="120" bind:value={displayName} placeholder="Issue tracker" />
    </label>
    <label>
      Description (optional)
      <input maxlength="500" bind:value={description} />
    </label>
    <label class="checkbox-label private-network-choice">
      <input type="checkbox" bind:checked={allowPrivateNetwork} />
      Allow private network addresses for this source
    </label>
    <p class="field-help">
      This permits loopback and private-network targets. Link-local and cloud metadata targets stay
      blocked.
    </p>
    <fieldset class="auth-fields">
      <legend>Authentication</legend>
      <label>
        Method
        <select
          bind:value={credentialDraft.type}
          onchange={() =>
            (credentialDraft = {
              ...credentialDraft,
              headerName: "",
              username: "",
              secret: "",
            })}
        >
          <option value="none">None</option>
          <option value="bearer">Bearer token</option>
          <option value="basic">Basic auth</option>
          <option value="api_key_header">API key header</option>
          <option value="oauth_access_token">OAuth access token (manual, advanced)</option>
        </select>
      </label>
      {#if credentialDraft.type === "api_key_header"}
        <label>
          Header name
          <input required autocomplete="off" bind:value={credentialDraft.headerName} />
        </label>
      {/if}
      {#if credentialDraft.type === "basic"}
        <label>
          Username
          <input required autocomplete="off" bind:value={credentialDraft.username} />
        </label>
      {/if}
      {#if credentialDraft.type !== "none"}
        <label>
          {credentialDraft.type === "bearer"
            ? "Bearer token"
            : credentialDraft.type === "basic"
              ? "Password"
              : credentialDraft.type === "oauth_access_token"
                ? "OAuth access token"
                : "Header value"}
          <input type="password" required autocomplete="off" bind:value={credentialDraft.secret} />
        </label>
      {/if}
      <p class="field-help">Credentials are encrypted locally and never shown again.</p>
    </fieldset>
    {#if localOptInMissing}
      <p class="notice warning" role="status">
        This looks like a local or private endpoint. Enable private network access to connect it.
      </p>
    {/if}
  </fieldset>

  <dl id="mcp-http-connection-policy" class="connection-policy">
    <div>
      <dt>Sessions</dt>
      <dd>Kept in memory and never displayed</dd>
    </div>
    <div>
      <dt>Redirects</dt>
      <dd>Disabled</dd>
    </div>
    <div>
      <dt>Proxies</dt>
      <dd>Ignored, Executor connects directly</dd>
    </div>
  </dl>

  {#if error !== null}
    <div id="mcp-http-error" tabindex="-1"><ErrorNotice {error} /></div>
  {/if}
  <button
    class="primary"
    type="submit"
    disabled={busy || disabled || localOptInMissing || credentialPayload === null}
  >
    {busy ? "Connecting..." : "Connect source"}
  </button>
</form>

<style>
  .mcp-form {
    display: grid;
    gap: 1rem;
    padding: 1.3rem;
  }

  fieldset {
    display: grid;
    gap: 1rem;
    min-width: 0;
    margin: 0;
    border: 0;
    padding: 0;
  }

  .auth-fields {
    border: 1px solid #293247;
    border-radius: 10px;
    padding: 0.85rem;
    background: #0d131d;
  }

  legend {
    color: #edf0f6;
    font-size: 1.05rem;
    font-weight: 750;
  }

  fieldset > p:first-of-type {
    margin: 0;
    color: #a8b2c4;
    line-height: 1.55;
  }

  .connection-policy {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.65rem;
    margin: 0;
  }

  .connection-policy div {
    border: 1px solid #293247;
    border-radius: 10px;
    padding: 0.75rem;
    background: #0d131d;
  }

  dt {
    color: #8f9bb1;
    font-size: 0.65rem;
    font-weight: 750;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  dd {
    margin: 0.3rem 0 0;
    color: #d7dde8;
    font-size: 0.76rem;
  }

  @media (max-width: 640px) {
    .connection-policy {
      grid-template-columns: 1fr;
    }
  }
</style>
