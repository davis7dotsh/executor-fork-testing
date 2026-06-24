<script lang="ts">
  import { tick } from "svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import type { ApiError, ApiResult, Source } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import { unexpectedRequestError } from "$lib/catalog-state";
  import {
    buildGraphqlCredential,
    clearGraphqlSecret,
    emptyGraphqlAuthDraft,
    normalizeGraphqlEndpoint,
    requiresGraphqlPrivateNetworkOptIn,
    type GraphqlAuthDraft,
    type GraphqlSourceInput,
  } from "$lib/graphql-source-state";

  let {
    create,
    oncreated,
  }: {
    create: (input: GraphqlSourceInput, signal: AbortSignal) => Promise<ApiResult<Source>>;
    oncreated: (source: Source) => void;
  } = $props();

  const auth = useAuthState();
  let endpoint = $state("");
  let displayName = $state("");
  let preferredSlug = $state("");
  let description = $state("");
  let allowPrivateNetwork = $state(false);
  let credentialDraft = $state<GraphqlAuthDraft>(emptyGraphqlAuthDraft());
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let credential = $derived(buildGraphqlCredential(credentialDraft));
  let normalizedEndpoint = $derived(normalizeGraphqlEndpoint(endpoint));
  let endpointInvalid = $derived(endpoint.trim() !== "" && normalizedEndpoint === null);
  let localOptInMissing = $derived(
    endpoint.trim() !== "" && requiresGraphqlPrivateNetworkOptIn(endpoint) && !allowPrivateNetwork,
  );
  let activeController: AbortController | null = null;
  let lifetime = 0;

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      activeController?.abort();
      activeController = null;
      credentialDraft = clearGraphqlSecret(credentialDraft);
    };
  });

  function changeAuthType() {
    credentialDraft = {
      ...credentialDraft,
      headerName: "",
      username: "",
      secret: "",
    };
  }

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    const currentCredential = credential;
    const currentEndpoint = normalizedEndpoint;
    if (busy || localOptInMissing || currentCredential === undefined || currentEndpoint === null) {
      return;
    }

    activeController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    activeController = controller;
    busy = true;
    error = null;
    credentialDraft = clearGraphqlSecret(credentialDraft);
    const settled = await create(
      {
        kind: "graphql",
        displayName: displayName.trim(),
        ...(preferredSlug.trim() ? { preferredSlug: preferredSlug.trim() } : {}),
        ...(description.trim() ? { description: description.trim() } : {}),
        endpoint: currentEndpoint,
        allowPrivateNetwork,
        ...(currentCredential === null ? {} : { credential: currentCredential }),
      },
      controller.signal,
    ).then(
      (result) => ({ ok: true, result }) as const,
      () => ({ ok: false }) as const,
    );
    if (owner !== lifetime || activeController !== controller || controller.signal.aborted) return;
    activeController = null;
    busy = false;

    if (!settled.ok) {
      error = unexpectedRequestError();
      await focusError();
      return;
    }
    if (!settled.result.ok) {
      if (!auth?.recoverFromApiError(settled.result.error)) {
        error = settled.result.error;
        await focusError();
      }
      return;
    }

    const source = settled.result.value;
    endpoint = "";
    displayName = "";
    preferredSlug = "";
    description = "";
    allowPrivateNetwork = false;
    credentialDraft = emptyGraphqlAuthDraft();
    oncreated(source);
  }

  async function focusError() {
    await tick();
    document.getElementById("graphql-source-error")?.focus();
  }
</script>

<form class="graphql-form" onsubmit={connect} aria-labelledby="graphql-form-title">
  <fieldset disabled={busy}>
    <legend id="graphql-form-title">GraphQL API</legend>
    <p>Connect an introspection-enabled GraphQL endpoint and import its queries and mutations.</p>
    <label>
      Endpoint
      <input
        type="url"
        required
        bind:value={endpoint}
        placeholder="https://api.example.com/graphql"
        aria-invalid={endpointInvalid}
        aria-describedby={endpointInvalid
          ? "graphql-endpoint-error graphql-connection-policy"
          : "graphql-connection-policy"}
      />
    </label>
    {#if endpointInvalid}
      <p id="graphql-endpoint-error" class="field-error">
        Use HTTPS without user info, query parameters, or fragments. Plain HTTP is allowed only for
        loopback development. Put secrets in Authentication.
      </p>
    {/if}
    <label>
      Source name
      <input required maxlength="120" bind:value={displayName} placeholder="Product API" />
    </label>
    <label>
      Preferred slug (optional)
      <input maxlength="80" autocomplete="off" bind:value={preferredSlug} placeholder="product" />
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
        <select bind:value={credentialDraft.type} onchange={changeAuthType}>
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
      {#if credentialDraft.type === "oauth_access_token"}
        <p class="field-help">Paste an access token managed outside Executor.</p>
      {/if}
      <p class="field-help">Credentials are encrypted locally and never shown again.</p>
    </fieldset>
    {#if localOptInMissing}
      <p class="notice warning" role="status">
        This looks like a local or private endpoint. Enable private network access to connect it.
      </p>
    {/if}
  </fieldset>

  <dl id="graphql-connection-policy" class="connection-policy">
    <div>
      <dt>Introspection</dt>
      <dd>Required when connecting and refreshing</dd>
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
    <div id="graphql-source-error" tabindex="-1"><ErrorNotice {error} /></div>
  {/if}
  <p class="field-help">
    Queries start Enabled, mutations start Ask, and deprecated operations start Disabled. Review or
    change any mode from Tools after connecting.
  </p>
  <button
    class="primary"
    type="submit"
    disabled={busy || localOptInMissing || normalizedEndpoint === null || credential === undefined}
  >
    {busy ? "Connecting..." : "Connect source"}
  </button>
</form>

<style>
  .graphql-form {
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
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  dd {
    margin: 0.35rem 0 0;
    color: #d9deea;
    font-size: 0.78rem;
  }

  @media (max-width: 720px) {
    .connection-policy {
      grid-template-columns: 1fr;
    }
  }
</style>
