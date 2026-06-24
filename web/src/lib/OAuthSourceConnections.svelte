<script lang="ts">
  import OAuthConnectionPanel from "$lib/OAuthConnectionPanel.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import {
    oauthCallbackConnectionId,
    oauthCallbackOutcomeNotice,
    type OAuthAvailableCredential,
    type OAuthConnectionList,
    type OAuthConnectionOperations,
    type OAuthOperationError,
  } from "$lib/oauth-connection-state";
  import { ApiError, type Source } from "$lib/api";

  type OAuthConnectionEntry = Omit<OAuthAvailableCredential, "managedOAuthEligible"> & {
    readonly managedOAuthEligible: boolean;
  };

  let {
    source,
    operations,
    callbackRefreshKey = null,
    disabled = false,
    onbusychange,
    oncallbackchecked,
  }: {
    source: Source;
    operations: OAuthConnectionOperations;
    callbackRefreshKey?: string | null;
    disabled?: boolean;
    onbusychange?: (busy: boolean) => void;
    oncallbackchecked?: (matched: boolean) => void;
  } = $props();

  const auth = useAuthState();
  let list = $state<OAuthConnectionList | null>(null);
  let loading = $state(false);
  let error = $state<OAuthOperationError | null>(null);
  let panelBusyKeys = $state<string[]>([]);
  let controller: AbortController | null = null;
  let generation = 0;
  let reportedBusy = false;
  let callbackNotice = $state<{
    key: string;
    tone: "success" | "error";
    message: string;
  } | null>(null);
  let latestCallbackKey: string | null = null;
  let entries = $derived(connectionEntries(list, source.kind));

  $effect(() => {
    const currentSourceId = source.id;
    const currentCallbackKey = callbackRefreshKey;
    const currentOperations = operations;
    const currentDisabled = disabled;
    if (currentCallbackKey !== null && currentCallbackKey !== latestCallbackKey) {
      latestCallbackKey = currentCallbackKey;
      callbackNotice = null;
    }
    if (currentDisabled) {
      controller?.abort();
      controller = null;
      loading = false;
      return;
    }

    const mine = ++generation;
    const request = new AbortController();
    controller?.abort();
    controller = request;
    loading = true;
    error = null;
    void currentOperations.load(currentSourceId, request.signal).then(
      (result) => {
        if (mine !== generation || request.signal.aborted) return;
        controller = null;
        loading = false;
        if (!result.ok) {
          const apiError = new ApiError(result.error);
          if (!auth.recoverFromApiError(apiError)) error = result.error;
          return;
        }
        list = result.value;
        const callbackConnectionId = oauthCallbackConnectionId(currentCallbackKey);
        const callbackMatches =
          callbackConnectionId !== null &&
          result.value.connections.some((connection) => connection.id === callbackConnectionId);
        if (callbackMatches) {
          const notice = oauthCallbackOutcomeNotice(currentCallbackKey ?? "", true);
          callbackNotice = { key: currentCallbackKey ?? "", ...notice };
        }
        if (callbackConnectionId !== null) oncallbackchecked?.(callbackMatches);
      },
      () => {
        if (mine !== generation || request.signal.aborted) return;
        controller = null;
        loading = false;
        error = localLoadError();
      },
    );

    return () => {
      generation += 1;
      request.abort();
      if (controller === request) controller = null;
    };
  });

  $effect(() => {
    const busy = loading || panelBusyKeys.length > 0;
    if (busy === reportedBusy) return;
    reportedBusy = busy;
    onbusychange?.(busy);
  });

  $effect(() => () => {
    controller?.abort();
    if (reportedBusy) onbusychange?.(false);
  });

  function setPanelBusy(credentialKey: string, busy: boolean) {
    panelBusyKeys = busy
      ? [...new Set([...panelBusyKeys, credentialKey])]
      : panelBusyKeys.filter((candidate) => candidate !== credentialKey);
  }

  function localLoadError(): OAuthOperationError {
    return {
      code: "network_error",
      displayMessage: "Executor could not load managed OAuth connections.",
      requestId: null,
      status: 0,
    };
  }

  function connectionEntries(current: OAuthConnectionList | null, sourceKind: Source["kind"]) {
    if (current === null) return [];
    const options = new Map<string, OAuthConnectionEntry>();
    for (const option of current.availableCredentials) options.set(option.credentialKey, option);
    for (const connection of current.connections) {
      if (options.has(connection.credentialKey)) continue;
      const protocol =
        sourceKind === "graphql"
          ? "graphql"
          : sourceKind === "mcp_http"
            ? "mcp_http"
            : sourceKind === "openapi"
              ? "openapi"
              : null;
      if (protocol === null) continue;
      options.set(connection.credentialKey, {
        credentialKey: connection.credentialKey,
        protocol,
        requestedScopes: connection.requestedScopes,
        managedOAuthEligible: connection.managedOAuthEligible,
      });
    }
    return [...options.values()].sort((left, right) =>
      left.credentialKey.localeCompare(right.credentialKey),
    );
  }
</script>

{#if loading && list === null}
  <p class="oauth-loading" aria-live="polite">Loading managed OAuth options...</p>
{:else if error !== null && list === null}
  <div class="notice error" role="alert">
    <strong>{error.displayMessage}</strong>
    {#if error.requestId !== null}<small>Request reference: <code>{error.requestId}</code></small
      >{/if}
  </div>
{:else if entries.length > 0}
  <section class="oauth-connections" aria-label={`Managed OAuth for ${source.displayName}`}>
    {#if callbackNotice !== null}
      <p
        class:error={callbackNotice.tone === "error"}
        class="notice callback-notice"
        role={callbackNotice.tone === "error" ? "alert" : "status"}
      >
        {callbackNotice.message}
      </p>
    {/if}
    <div class="oauth-intro">
      <div>
        <p class="eyebrow">Managed OAuth</p>
        <h3>Provider connections</h3>
      </div>
      <p>
        Executor stores refreshable tokens locally. Manual access tokens remain available under
        advanced credential settings.
      </p>
    </div>
    {#each entries as entry (entry.credentialKey)}
      <OAuthConnectionPanel
        sourceId={source.id}
        credentialKey={entry.credentialKey}
        defaultRequestedScopes={entry.requestedScopes}
        discoveryType={entry.protocol === "mcp_http" ? "mcp" : "issuer"}
        configurationDisabled={!entry.managedOAuthEligible}
        {operations}
        {callbackRefreshKey}
        {disabled}
        onbusychange={(busy) => setPanelBusy(entry.credentialKey, busy)}
      />
    {/each}
  </section>
{/if}

<style>
  .oauth-connections {
    display: grid;
    flex-basis: 100%;
    gap: 1rem;
    width: 100%;
    border-top: 1px solid #293247;
    padding-top: 1rem;
  }

  .oauth-intro {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
  }

  .oauth-intro h3,
  .oauth-intro p {
    margin: 0;
  }

  .oauth-intro > p {
    max-width: 32rem;
    color: #9da8bb;
    font-size: 0.76rem;
    line-height: 1.5;
  }

  .oauth-loading {
    flex-basis: 100%;
    margin: 0;
    color: #a8b2c4;
    font-size: 0.78rem;
  }

  .callback-notice {
    margin: 0;
  }

  @media (max-width: 560px) {
    .oauth-intro {
      flex-direction: column;
    }
  }
</style>
