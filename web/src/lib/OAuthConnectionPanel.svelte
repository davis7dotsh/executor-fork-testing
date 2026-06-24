<script lang="ts">
  import { tick } from "svelte";
  import { ApiError } from "$lib/api";
  import { useAuthState } from "$lib/auth.svelte";
  import { copyText } from "$lib/clipboard";
  import {
    buildOAuthConnectionInput,
    canDisconnectOAuth,
    draftFromOAuthSummary,
    emptyOAuthDraft,
    oauthStatusLabel,
    oauthStatusTone,
    safeAuthorizationUrl,
    type OAuthConnectionDraft,
    type OAuthConnectionOperations,
    type OAuthConnectionSummary,
    type OAuthOperationError,
  } from "$lib/oauth-connection-state";

  let {
    sourceId,
    credentialKey,
    callbackRefreshKey = null,
    emptyRevision = 0,
    defaultRequestedScopes = [],
    discoveryType = "issuer",
    configurationDisabled = false,
    disabled = false,
    operations,
    navigate,
    onbusychange,
  }: {
    sourceId: string;
    credentialKey: string;
    callbackRefreshKey?: string | null;
    emptyRevision?: number;
    defaultRequestedScopes?: readonly string[];
    discoveryType?: "issuer" | "mcp";
    configurationDisabled?: boolean;
    disabled?: boolean;
    operations: OAuthConnectionOperations;
    navigate?: (url: string) => void;
    onbusychange?: (busy: boolean) => void;
  } = $props();

  const auth = useAuthState();
  let summary = $state<OAuthConnectionSummary | null>(null);
  let draft = $state<OAuthConnectionDraft>(emptyOAuthDraft());
  let revision = $state(0);
  let loading = $state(true);
  let busy = $state<"save" | "authorize" | "disconnect" | "remove" | null>(null);
  let dirty = $state(false);
  let draftConflict = $state(false);
  let conflictLatestLoaded = $state(false);
  let conflictRefreshFailed = $state(false);
  let error = $state<OAuthOperationError | null>(null);
  let notice = $state<string | null>(null);
  let confirmingDisconnect = $state(false);
  let confirmingDelete = $state(false);
  let copyStatus = $state("");
  let callbackField = $state<HTMLInputElement>();
  let disconnectButton = $state<HTMLButtonElement>();
  let disconnectConfirmButton = $state<HTMLButtonElement>();
  let deleteButton = $state<HTMLButtonElement>();
  let deleteConfirmButton = $state<HTMLButtonElement>();
  let refreshNonce = $state(0);
  let loadGeneration = 0;
  let lifetime = 0;
  let loadController: AbortController | null = null;
  let mutationController: AbortController | null = null;
  let loadedIdentity = "";
  let reportedBusy = false;
  let panelId = $derived(`oauth-${safeDomId(sourceId)}-${safeDomId(credentialKey)}`);
  let saveInput = $derived(buildOAuthConnectionInput(draft, revision, discoveryType));
  let statusTone = $derived(summary === null ? "neutral" : oauthStatusTone(summary.status));
  let configurationUnavailable = $derived(
    configurationDisabled || summary?.managedOAuthEligible === false,
  );

  $effect(() => {
    lifetime += 1;
    return () => {
      lifetime += 1;
      loadController?.abort();
      mutationController?.abort();
      draft = { ...draft, clientSecret: "" };
      if (reportedBusy) onbusychange?.(false);
    };
  });

  $effect(() => {
    const active = loading || busy !== null;
    if (active === reportedBusy) return;
    reportedBusy = active;
    onbusychange?.(active);
  });

  $effect(() => {
    const currentSourceId = sourceId;
    const currentCredentialKey = credentialKey;
    const currentCallbackKey = callbackRefreshKey;
    const currentEmptyRevision = emptyRevision;
    const currentDefaultScopes = defaultRequestedScopes;
    const currentOperations = operations;
    const currentRefreshNonce = refreshNonce;
    const currentDisabled = disabled;
    const identity = `${currentSourceId}\u0000${currentCredentialKey}`;
    void currentCallbackKey;
    void currentRefreshNonce;

    mutationController?.abort();
    mutationController = null;
    busy = null;
    if (currentDisabled) {
      loadController?.abort();
      loadController = null;
      loading = false;
      return;
    }

    if (loadedIdentity !== identity) {
      loadedIdentity = identity;
      summary = null;
      draft = emptyDraftWithScopes(currentDefaultScopes);
      revision = currentEmptyRevision;
      dirty = false;
      draftConflict = false;
      conflictLatestLoaded = false;
      conflictRefreshFailed = false;
      confirmingDisconnect = false;
      confirmingDelete = false;
      copyStatus = "";
      notice = null;
    }

    const generation = ++loadGeneration;
    const controller = new AbortController();
    loadController?.abort();
    loadController = controller;
    loading = true;
    error = null;

    void currentOperations.load(currentSourceId, controller.signal).then(
      (result) => {
        if (generation !== loadGeneration || controller.signal.aborted) return;
        loadController = null;
        loading = false;
        if (!result.ok) {
          if (auth?.recoverFromApiError(new ApiError(result.error))) return;
          error = result.error;
          if (draftConflict) conflictRefreshFailed = true;
          return;
        }
        const connection =
          result.value.connections.find(
            (candidate) => candidate.credentialKey === currentCredentialKey,
          ) ?? null;
        summary = connection;
        if (connection === null || !canDisconnectOAuth(connection.status)) {
          confirmingDisconnect = false;
        }
        if (!dirty) {
          revision = connection?.revision ?? currentEmptyRevision;
          draft =
            connection === null
              ? emptyDraftWithScopes(currentDefaultScopes)
              : draftFromOAuthSummary(connection);
          draftConflict = false;
          conflictRefreshFailed = false;
        } else if (draftConflict) {
          conflictLatestLoaded = true;
          conflictRefreshFailed = false;
          error = {
            code: "revision_conflict",
            displayMessage:
              "This OAuth configuration changed elsewhere. Discard your draft before editing the latest version.",
            requestId: null,
            status: 409,
          };
          void focusError();
        }
      },
      () => {
        if (generation !== loadGeneration || controller.signal.aborted) return;
        loadController = null;
        loading = false;
        error = localOperationError();
        if (draftConflict) conflictRefreshFailed = true;
      },
    );

    return () => {
      loadGeneration += 1;
      controller.abort();
      if (loadController === controller) loadController = null;
    };
  });

  function updateDraft(patch: Partial<OAuthConnectionDraft>) {
    draft = { ...draft, ...patch };
    dirty = true;
    notice = null;
    if (!draftConflict) error = null;
  }

  function changeClientKind(kind: OAuthConnectionDraft["clientKind"]) {
    updateDraft({
      clientKind: kind,
      clientSecretAction:
        kind === "public" ? "clear" : summary?.hasClientSecret ? "preserve" : "replace",
      clientSecret: "",
    });
  }

  function changeSecretAction(action: OAuthConnectionDraft["clientSecretAction"]) {
    updateDraft({ clientSecretAction: action, clientSecret: "" });
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    const input = saveInput;
    if (input === null || busy !== null || loading || disabled || configurationUnavailable) return;
    draft = { ...draft, clientSecret: "" };
    await mutate(
      "save",
      (signal) => operations.save(sourceId, credentialKey, input, signal),
      (next) => {
        summary = next;
        revision = next.revision;
        draft = draftFromOAuthSummary(next);
        dirty = false;
        draftConflict = false;
        conflictLatestLoaded = false;
        conflictRefreshFailed = false;
        notice = "OAuth configuration saved. Connect when you are ready to authorize it.";
      },
    );
  }

  async function connect() {
    if (
      summary === null ||
      dirty ||
      busy !== null ||
      loading ||
      disabled ||
      configurationUnavailable
    )
      return;
    await mutate(
      "authorize",
      (signal) =>
        operations.authorize(
          sourceId,
          credentialKey,
          { expectedRevision: summary?.revision ?? revision },
          signal,
        ),
      (authorization) => {
        const destination = safeAuthorizationUrl(authorization.authorizationUrl);
        if (destination === null) {
          error = {
            code: "invalid_authorization_url",
            displayMessage: "Executor returned an invalid OAuth authorization destination.",
            requestId: null,
            status: 502,
          };
          return;
        }
        if (navigate === undefined) {
          window.location.assign(destination);
        } else {
          navigate(destination);
        }
      },
    );
  }

  async function disconnect() {
    if (
      summary === null ||
      !canDisconnectOAuth(summary.status) ||
      busy !== null ||
      loading ||
      disabled
    )
      return;
    await mutate(
      "disconnect",
      (signal) =>
        operations.disconnect(
          sourceId,
          credentialKey,
          { expectedRevision: summary?.revision ?? revision },
          signal,
        ),
      (next) => {
        summary = next;
        revision = next.revision;
        draft = draftFromOAuthSummary(next);
        dirty = false;
        draftConflict = false;
        conflictLatestLoaded = false;
        conflictRefreshFailed = false;
        confirmingDisconnect = false;
        notice = "OAuth tokens disconnected. The saved client configuration remains available.";
        void focusNotice();
      },
    );
  }

  async function remove() {
    if (summary === null || busy !== null || loading || disabled) return;
    await mutate(
      "remove",
      (signal) =>
        operations.remove(
          sourceId,
          credentialKey,
          { expectedRevision: summary?.revision ?? revision },
          signal,
        ),
      () => {
        summary = null;
        revision = emptyRevision;
        draft = emptyDraftWithScopes(defaultRequestedScopes);
        dirty = false;
        draftConflict = false;
        conflictLatestLoaded = false;
        conflictRefreshFailed = false;
        confirmingDelete = false;
        notice = "OAuth configuration deleted.";
        void focusNotice();
      },
    );
  }

  async function mutate<Value>(
    kind: NonNullable<typeof busy>,
    operation: (
      signal: AbortSignal,
    ) => Promise<
      | { readonly ok: true; readonly value: Value }
      | { readonly ok: false; readonly error: OAuthOperationError }
    >,
    complete: (value: Value) => void,
  ) {
    mutationController?.abort();
    const controller = new AbortController();
    const owner = lifetime;
    mutationController = controller;
    busy = kind;
    error = null;
    notice = null;
    const settled = await operation(controller.signal).then(
      (result) => ({ ok: true, result }) as const,
      () => ({ ok: false }) as const,
    );
    if (owner !== lifetime || mutationController !== controller || controller.signal.aborted)
      return;
    mutationController = null;
    busy = null;
    draft = { ...draft, clientSecret: "" };

    if (!settled.ok) {
      error = localOperationError();
      await focusError();
      return;
    }
    if (!settled.result.ok) {
      if (auth?.recoverFromApiError(new ApiError(settled.result.error))) return;
      error = settled.result.error;
      if (settled.result.error.status === 409) {
        draftConflict = true;
        conflictLatestLoaded = false;
        conflictRefreshFailed = false;
        refreshNonce += 1;
      }
      await focusError();
      return;
    }
    complete(settled.result.value);
  }

  async function copyCallback() {
    const field = callbackField;
    const callbackUrl = summary?.callbackUrl;
    if (field === undefined || callbackUrl === undefined) return;
    copyStatus = (await copyText(callbackUrl, field)) ? "Callback URL copied." : "Copy failed.";
  }

  async function focusError() {
    await tick();
    document.getElementById(`${panelId}-error`)?.focus();
  }

  async function focusNotice() {
    await tick();
    document.getElementById(`${panelId}-notice`)?.focus();
  }

  function discardConflictedDraft() {
    draft = summary === null ? emptyOAuthDraft() : draftFromOAuthSummary(summary);
    revision = summary?.revision ?? emptyRevision;
    dirty = false;
    draftConflict = false;
    conflictLatestLoaded = false;
    conflictRefreshFailed = false;
    error = null;
    notice = "Latest OAuth configuration loaded.";
    void focusNotice();
  }

  function retryConflictRefresh() {
    conflictRefreshFailed = false;
    refreshNonce += 1;
  }

  async function showDisconnectConfirmation() {
    confirmingDelete = false;
    confirmingDisconnect = true;
    await tick();
    disconnectConfirmButton?.focus();
  }

  async function cancelDisconnectConfirmation() {
    confirmingDisconnect = false;
    await tick();
    disconnectButton?.focus();
  }

  async function showDeleteConfirmation() {
    confirmingDisconnect = false;
    confirmingDelete = true;
    await tick();
    deleteConfirmButton?.focus();
  }

  async function cancelDeleteConfirmation() {
    confirmingDelete = false;
    await tick();
    deleteButton?.focus();
  }

  function handleConfirmationKeydown(event: KeyboardEvent, cancel: () => Promise<void>) {
    if (event.key !== "Escape") return;
    event.preventDefault();
    void cancel();
  }

  function safeDomId(value: string) {
    return value.replace(/[^a-zA-Z0-9_-]/gu, "-");
  }

  function localOperationError(): OAuthOperationError {
    return {
      code: "network_error",
      displayMessage: "Executor could not complete the OAuth request.",
      requestId: null,
      status: 0,
    };
  }

  function emptyDraftWithScopes(scopes: readonly string[]) {
    return { ...emptyOAuthDraft(), scopes: scopes.join(" ") };
  }
</script>

<section class="oauth-panel" aria-labelledby={`${panelId}-title`}>
  <div class="oauth-heading">
    <div>
      <p class="eyebrow">Managed OAuth</p>
      <h3 id={`${panelId}-title`}>{credentialKey}</h3>
    </div>
    {#if summary !== null}
      <span
        class:connected={statusTone === "connected"}
        class:error={statusTone === "error"}
        class:pending={statusTone === "pending"}
        class="oauth-status"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {oauthStatusLabel(summary.status)}
      </span>
    {/if}
  </div>

  {#if loading}
    <p class="oauth-loading" aria-live="polite">Loading OAuth configuration...</p>
  {:else}
    {#if summary !== null}
      <dl class="oauth-summary">
        <div>
          <dt>Issuer</dt>
          <dd>{summary.issuer}</dd>
        </div>
        <div>
          <dt>Client</dt>
          <dd>{summary.clientAuthMethod === "none" ? "Public" : "Confidential"}</dd>
        </div>
        <div>
          <dt>Granted scopes</dt>
          <dd>{summary.grantedScopes.length > 0 ? summary.grantedScopes.join(" ") : "None yet"}</dd>
        </div>
        <div>
          <dt>Refresh token</dt>
          <dd>{summary.hasRefreshToken ? "Stored securely" : "Not stored"}</dd>
        </div>
      </dl>

      <div class="callback-field">
        <label for={`${panelId}-callback`}>Exact callback URL</label>
        <div>
          <input
            id={`${panelId}-callback`}
            bind:this={callbackField}
            readonly
            value={summary.callbackUrl}
          />
          <button type="button" onclick={copyCallback}>Copy</button>
        </div>
        <p class="field-help">Register this exact URL with the OAuth provider.</p>
        <p class="copy-status" role="status">{copyStatus}</p>
      </div>
    {/if}

    <form class="oauth-form" onsubmit={save}>
      {#if configurationUnavailable}
        <p class="notice warning" role="status">
          This source no longer offers this managed OAuth credential. Disconnect or delete the saved
          connection, or refresh the source configuration.
        </p>
      {/if}
      <fieldset disabled={busy !== null || disabled || configurationUnavailable}>
        <legend>{summary === null ? "Configure connection" : "Connection settings"}</legend>
        <label>
          {discoveryType === "mcp" ? "Authorization server override (optional)" : "Issuer URL"}
          <input
            type="url"
            required={discoveryType === "issuer"}
            autocomplete="url"
            value={draft.issuer}
            oninput={(event) => updateDraft({ issuer: event.currentTarget.value })}
            placeholder="https://identity.example.com"
          />
        </label>
        <label>
          Client type
          <select
            value={draft.clientKind}
            onchange={(event) =>
              changeClientKind(event.currentTarget.value as "public" | "confidential")}
          >
            <option value="public">Public client (PKCE)</option>
            <option value="confidential">Confidential client</option>
          </select>
        </label>
        <label>
          Client ID
          <input
            required
            autocomplete="off"
            value={draft.clientId}
            oninput={(event) => updateDraft({ clientId: event.currentTarget.value })}
          />
        </label>
        {#if draft.clientKind === "confidential"}
          <label>
            Client authentication
            <select
              value={draft.clientAuthMethod}
              onchange={(event) =>
                updateDraft({
                  clientAuthMethod: event.currentTarget.value as
                    | "client_secret_basic"
                    | "client_secret_post",
                })}
            >
              <option value="client_secret_basic">HTTP Basic</option>
              <option value="client_secret_post">Request body</option>
            </select>
          </label>
          <fieldset class="secret-fieldset">
            <legend>Client secret</legend>
            {#if summary?.hasClientSecret}
              <label class="radio-label">
                <input
                  type="radio"
                  name={`${panelId}-secret-action`}
                  checked={draft.clientSecretAction === "preserve"}
                  onchange={() => changeSecretAction("preserve")}
                />
                Preserve the saved secret
              </label>
            {/if}
            <label class="radio-label">
              <input
                type="radio"
                name={`${panelId}-secret-action`}
                checked={draft.clientSecretAction === "replace"}
                onchange={() => changeSecretAction("replace")}
              />
              {summary?.hasClientSecret ? "Replace the saved secret" : "Set a client secret"}
            </label>
            {#if draft.clientSecretAction === "replace"}
              <label>
                New client secret
                <input
                  type="password"
                  required
                  autocomplete="new-password"
                  value={draft.clientSecret}
                  oninput={(event) => updateDraft({ clientSecret: event.currentTarget.value })}
                />
              </label>
            {/if}
          </fieldset>
        {:else if summary?.hasClientSecret}
          <p class="notice warning" role="status">
            Saving as a public client clears the stored client secret.
          </p>
        {/if}
        <label>
          Requested scopes
          <input
            autocomplete="off"
            value={draft.scopes}
            oninput={(event) => updateDraft({ scopes: event.currentTarget.value })}
            placeholder="openid profile offline_access"
          />
          <small>Separate scopes with spaces, commas, or new lines.</small>
        </label>
      </fieldset>

      <div class="button-row">
        <button
          class="primary"
          type="submit"
          disabled={disabled ||
            configurationUnavailable ||
            busy !== null ||
            saveInput === null ||
            !dirty ||
            draftConflict}
        >
          {busy === "save" ? "Saving..." : "Save configuration"}
        </button>
        <button
          type="button"
          disabled={disabled ||
            configurationUnavailable ||
            summary === null ||
            dirty ||
            busy !== null}
          onclick={connect}
        >
          {busy === "authorize" ? "Starting..." : "Connect OAuth"}
        </button>
      </div>
      {#if dirty && summary !== null}
        <p class="field-help">Save your changes before starting the OAuth authorization.</p>
      {/if}
    </form>

    {#if summary !== null}
      <div class="oauth-actions">
        {#if confirmingDisconnect}
          <dialog
            open
            class="inline-confirm-dialog"
            aria-labelledby={`${panelId}-disconnect-title`}
            onkeydown={(event) => handleConfirmationKeydown(event, cancelDisconnectConfirmation)}
          >
            <strong id={`${panelId}-disconnect-title`}>Disconnect OAuth tokens?</strong>
            <p>The saved client configuration will remain available.</p>
            <div class="button-row">
              <button
                bind:this={disconnectConfirmButton}
                type="button"
                disabled={disabled || busy !== null || !canDisconnectOAuth(summary.status)}
                onclick={disconnect}
              >
                {busy === "disconnect" ? "Disconnecting..." : "Disconnect tokens"}
              </button>
              <button
                type="button"
                disabled={disabled || busy !== null}
                onclick={cancelDisconnectConfirmation}>Cancel</button
              >
            </div>
          </dialog>
        {:else}
          <button
            bind:this={disconnectButton}
            type="button"
            disabled={disabled || busy !== null || !canDisconnectOAuth(summary.status)}
            onclick={showDisconnectConfirmation}
          >
            Disconnect tokens
          </button>
        {/if}
        {#if confirmingDelete}
          <dialog
            open
            class="inline-confirm-dialog"
            aria-labelledby={`${panelId}-delete-title`}
            onkeydown={(event) => handleConfirmationKeydown(event, cancelDeleteConfirmation)}
          >
            <strong id={`${panelId}-delete-title`}>Delete this OAuth configuration?</strong>
            <p>This removes the client configuration and all stored OAuth tokens.</p>
            <div class="button-row">
              <button
                bind:this={deleteConfirmButton}
                class="danger-button"
                type="button"
                disabled={disabled || busy !== null}
                onclick={remove}
              >
                {busy === "remove" ? "Deleting..." : "Delete"}
              </button>
              <button
                type="button"
                disabled={disabled || busy !== null}
                onclick={cancelDeleteConfirmation}>Cancel</button
              >
            </div>
          </dialog>
        {:else}
          <button
            bind:this={deleteButton}
            class="danger-link"
            type="button"
            disabled={disabled || busy !== null}
            onclick={showDeleteConfirmation}>Delete configuration</button
          >
        {/if}
      </div>
    {/if}
  {/if}

  {#if notice !== null}
    <p id={`${panelId}-notice`} class="notice" role="status" tabindex="-1">{notice}</p>
  {/if}
  {#if error !== null}
    <div id={`${panelId}-error`} class="notice error" role="alert" tabindex="-1">
      <strong>{error.displayMessage}</strong>
      {#if error.requestId !== null}<small>Request reference: <code>{error.requestId}</code></small
        >{/if}
    </div>
    {#if draftConflict && conflictLatestLoaded}
      <button type="button" onclick={discardConflictedDraft}>Discard draft and load latest</button>
    {:else if draftConflict && conflictRefreshFailed}
      <button type="button" onclick={retryConflictRefresh}>Retry loading latest</button>
    {:else if draftConflict}
      <p class="field-help" aria-live="polite">Loading the latest OAuth configuration...</p>
    {/if}
  {/if}
</section>

<style>
  .oauth-panel,
  .oauth-form,
  .oauth-form fieldset,
  .secret-fieldset {
    display: grid;
    gap: 1rem;
  }

  .oauth-panel {
    width: 100%;
    border-top: 1px solid #293247;
    padding-top: 1rem;
  }

  .oauth-heading,
  .oauth-actions,
  .callback-field > div,
  .inline-confirm-dialog .button-row {
    display: flex;
    gap: 0.7rem;
    align-items: center;
  }

  .oauth-heading {
    justify-content: space-between;
  }

  .oauth-heading h3,
  .oauth-heading p,
  .oauth-loading {
    margin: 0;
  }

  .oauth-status {
    border: 1px solid #4a556d;
    border-radius: 999px;
    padding: 0.28rem 0.55rem;
    color: #c1cada;
    background: #171e2b;
    font-size: 0.68rem;
    font-weight: 750;
  }

  .oauth-status.connected {
    border-color: #315b50;
    color: #75d5b3;
    background: #11231f;
  }

  .oauth-status.error {
    border-color: #6a3c48;
    color: #f4bdc8;
    background: #24141a;
  }

  .oauth-status.pending {
    border-color: #75683f;
    color: #f0e2b7;
    background: #252015;
  }

  .oauth-summary {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.7rem;
    margin: 0;
  }

  .oauth-summary div {
    min-width: 0;
    border: 1px solid #283146;
    border-radius: 10px;
    padding: 0.75rem;
    background: #0d131d;
  }

  .oauth-summary dt {
    color: #8f9bb1;
    font-size: 0.65rem;
    font-weight: 750;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .oauth-summary dd {
    margin: 0.3rem 0 0;
    overflow-wrap: anywhere;
    color: #d7dde8;
    font-size: 0.78rem;
  }

  .oauth-form > fieldset,
  .secret-fieldset {
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

  .callback-field > div input {
    min-width: 0;
  }

  .callback-field > div button {
    flex: 0 0 auto;
  }

  .copy-status {
    min-height: 1.2rem;
    margin: 0.25rem 0 0;
    color: #a8b2c4;
    font-size: 0.74rem;
  }

  .radio-label {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .radio-label input {
    width: auto;
    margin: 0;
  }

  .oauth-actions {
    flex-wrap: wrap;
    justify-content: space-between;
    border-top: 1px solid #293247;
    padding-top: 1rem;
  }

  .inline-confirm-dialog {
    display: grid;
    flex: 1 1 100%;
    gap: 0.65rem;
    width: 100%;
    margin: 0;
    border: 1px solid #4a3a45;
    border-radius: 10px;
    padding: 0.85rem;
    color: #f1c2cc;
    background: #21151a;
    font-size: 0.78rem;
  }

  .inline-confirm-dialog p {
    margin: 0;
    color: #cbaab2;
  }

  @media (max-width: 560px) {
    .oauth-summary {
      grid-template-columns: 1fr;
    }

    .callback-field > div,
    .oauth-actions {
      align-items: stretch;
      flex-direction: column;
    }
  }
</style>
