<script lang="ts">
  import { beforeNavigate, goto } from "$app/navigation";
  import { onMount } from "svelte";
  import DashboardShell from "$lib/DashboardShell.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import {
    createToken,
    listTokens,
    revokeToken,
    type ApiError,
    type CreatedToken,
    type TokenMetadata,
  } from "$lib/api";
  import { copyText } from "$lib/clipboard";
  import { canCreateToken, shouldBlockTokenExit, tokenListView } from "$lib/token-page-state";
  import { focusRevealedToken } from "$lib/token-reveal-focus";

  const auth = useAuthState();
  const activeControllers = new Set<AbortController>();
  let name = $state("");
  let tokens = $state<TokenMetadata[]>([]);
  let revealed = $state<CreatedToken | null>(null);
  let tokenField = $state<HTMLInputElement>();
  let pendingRevoke = $state<TokenMetadata | null>(null);
  let revokeDialog = $state<HTMLDialogElement>();
  let loading = $state(true);
  let hasLoaded = $state(false);
  let creating = $state(false);
  let revoking = $state(false);
  let listError = $state<ApiError | null>(null);
  let mutationError = $state<ApiError | null>(null);
  let revokeError = $state<ApiError | null>(null);
  let copyStatus = $state<"idle" | "copied" | "failed">("idle");
  let navigationBlocked = $state(false);
  let listGeneration = 0;
  let lifetime = 0;
  let hasUnsavedToken = $derived(revealed !== null);
  let canCreate = $derived(canCreateToken({ name, creating, hasUnsavedToken }));
  let listView = $derived(
    tokenListView({
      loading,
      hasLoaded,
      hasError: listError !== null,
      tokenCount: tokens.length,
    }),
  );
  let copyMessage = $derived(
    copyStatus === "copied"
      ? "Token copied to the clipboard."
      : copyStatus === "failed"
        ? "Automatic copy failed. Select the token and copy it manually."
        : "The token is ready to copy.",
  );

  beforeNavigate(({ cancel }) => {
    if (!shouldBlockTokenExit({ creating, hasUnsavedToken })) return;
    navigationBlocked = true;
    cancel();
  });

  onMount(() => {
    lifetime += 1;
    void refresh();
    return () => {
      lifetime += 1;
      listGeneration += 1;
      for (const controller of activeControllers) controller.abort();
      activeControllers.clear();
    };
  });

  $effect(() => {
    const dialog = revokeDialog;
    const shouldOpen = pendingRevoke !== null;
    if (dialog === undefined) return;

    if (shouldOpen && !dialog.open) dialog.showModal();
    if (!shouldOpen && dialog.open) dialog.close();

    return () => {
      if (dialog.open) dialog.close();
    };
  });

  async function refresh() {
    const mine = ++listGeneration;
    const owner = lifetime;
    const controller = startRequest();
    loading = true;
    listError = null;
    const result = await listTokens(undefined, controller.signal);
    activeControllers.delete(controller);
    if (mine !== listGeneration || owner !== lifetime) return;

    if (result.ok) {
      tokens = [...result.value];
      hasLoaded = true;
    } else if (!auth.recoverFromApiError(result.error)) {
      listError = result.error;
    }
    loading = false;
  }

  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!canCreate) return;

    const owner = lifetime;
    const controller = startRequest();
    creating = true;
    mutationError = null;
    copyStatus = "idle";
    navigationBlocked = false;
    const result = await createToken(name.trim(), undefined, controller.signal);
    activeControllers.delete(controller);
    if (owner !== lifetime) return;

    if (result.ok) {
      const createdToken = result.value;
      revealed = createdToken;
      name = "";
      await focusRevealedToken({
        token: createdToken,
        currentToken: () => revealed,
        field: () => tokenField,
        isCurrentLifetime: () => owner === lifetime,
      });
      if (owner !== lifetime || revealed !== createdToken) return;
    } else if (!auth.recoverFromApiError(result.error)) {
      mutationError = result.error;
    }
    creating = false;
  }

  async function copyRevealed() {
    const current = revealed;
    const field = tokenField;
    const owner = lifetime;
    if (current === null || field === undefined) return;

    const copied = await copyText(current.token, field);
    if (owner !== lifetime || current !== revealed) return;
    copyStatus = copied ? "copied" : "failed";
  }

  async function confirmRevoke() {
    const token = pendingRevoke;
    if (token === null) return;

    const owner = lifetime;
    const controller = startRequest();
    revoking = true;
    revokeError = null;
    const result = await revokeToken(token.id, undefined, controller.signal);
    activeControllers.delete(controller);
    if (owner !== lifetime || token !== pendingRevoke) return;

    if (result.ok) {
      pendingRevoke = null;
      revoking = false;
      void refresh();
      return;
    }
    if (!auth.recoverFromApiError(result.error)) revokeError = result.error;
    revoking = false;
  }

  function askToRevoke(token: TokenMetadata) {
    revokeError = null;
    pendingRevoke = token;
  }

  function dismissReveal() {
    revealed = null;
    copyStatus = "idle";
    navigationBlocked = false;
    if (!auth.authenticated) {
      void goto("/login", { replaceState: true });
      return;
    }
    void refresh();
  }

  function guardBeforeUnload(event: BeforeUnloadEvent) {
    if (!shouldBlockTokenExit({ creating, hasUnsavedToken })) return;
    event.preventDefault();
    event.returnValue = "";
  }

  function startRequest() {
    const controller = new AbortController();
    activeControllers.add(controller);
    return controller;
  }

  function displayDate(timestamp: number | null) {
    return timestamp === null ? "Never" : new Date(timestamp * 1000).toLocaleString();
  }
</script>

<svelte:window onbeforeunload={guardBeforeUnload} />

<DashboardShell
  title="API tokens"
  description="Issue gateway credentials without giving agents dashboard access."
>
  <div class="token-layout">
    <section class="surface token-form">
      <p class="eyebrow">New credential</p>
      <h2>Create an API token</h2>
      <p>
        Name it for the device or agent that will use it. All tokens share the enabled tool set.
      </p>
      <form onsubmit={create}>
        <label for="token-name">Token name</label>
        <input
          id="token-name"
          bind:value={name}
          placeholder="Laptop coding agent"
          autocomplete="off"
          required
          maxlength="80"
          disabled={creating || hasUnsavedToken}
          aria-describedby={hasUnsavedToken ? "token-create-help" : undefined}
        />
        {#if hasUnsavedToken}
          <small id="token-create-help">Save the revealed token before creating another.</small>
        {/if}
        {#if mutationError !== null}<ErrorNotice error={mutationError} />{/if}
        <button class="primary" type="submit" disabled={!canCreate}>
          {creating ? "Creating token..." : "Create token"}
        </button>
      </form>
    </section>

    {#if revealed !== null}
      <section class="surface reveal-card">
        <p class="eyebrow">Shown once</p>
        <h2>Copy this token now.</h2>
        <label for="revealed-token">API token</label>
        <input
          id="revealed-token"
          class="token-secret"
          bind:this={tokenField}
          value={revealed.token}
          readonly
          autocomplete="off"
          spellcheck="false"
          aria-describedby="token-secret-help copy-status"
          onfocus={(event) => event.currentTarget.select()}
        />
        <p id="token-secret-help">
          Executor stores only a keyed digest. This secret cannot be recovered later.
        </p>
        <div class="button-row">
          <button class="primary" type="button" onclick={copyRevealed}>Copy token</button>
          <button type="button" onclick={dismissReveal}>I saved it</button>
        </div>
        <p id="copy-status" class="copy-status" role="status" aria-live="polite">
          {copyMessage}
        </p>
        {#if navigationBlocked}
          <p class="notice warning" role="status">
            Save the token and choose “I saved it” before leaving this page.
          </p>
        {/if}
      </section>
    {/if}
  </div>

  {#if listView === "stale" && listError !== null}
    <div class="stale-notice" role="status">
      <strong>Showing the last successfully loaded token list.</strong>
      <ErrorNotice error={listError} />
    </div>
  {/if}

  <section class="surface table-card" aria-busy={loading}>
    <div class="section-heading">
      <div>
        <p class="eyebrow">Gateway access</p>
        <h2>Issued tokens</h2>
      </div>
      <button type="button" onclick={refresh} disabled={loading}>
        {loading && hasLoaded ? "Refreshing..." : "Refresh"}
      </button>
    </div>

    {#if listView === "loading"}
      <p class="table-empty" aria-live="polite">Loading tokens...</p>
    {:else if listView === "unavailable" && listError !== null}
      <div class="table-unavailable">
        <strong>Token list unavailable</strong>
        <p>We could not load your API tokens. Try again to see which tokens have been issued.</p>
        <ErrorNotice error={listError} />
      </div>
    {:else if listView === "empty"}
      <p class="table-empty">No API tokens have been issued.</p>
    {:else if listView === "stale" && tokens.length === 0}
      <p class="table-empty">The last successful load contained no API tokens.</p>
    {:else}
      <div class="table-scroll">
        <table>
          <caption>API tokens issued by this Executor instance</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Token</th>
              <th scope="col">Last used</th>
              <th scope="col">Status</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {#each tokens as token (token.id)}
              <tr>
                <td data-label="Name">
                  <strong>{token.name}</strong><small>Created {displayDate(token.createdAt)}</small>
                </td>
                <td data-label="Token"><code>{token.maskedToken}</code></td>
                <td data-label="Last used">{displayDate(token.lastUsedAt)}</td>
                <td data-label="Status">
                  <span class:revoked={token.revokedAt !== null} class="status-pill">
                    {token.revokedAt === null ? "Active" : "Revoked"}
                  </span>
                </td>
                <td data-label="Action">
                  <button
                    class="danger-link"
                    type="button"
                    disabled={token.revokedAt !== null}
                    aria-label={`Revoke ${token.name}`}
                    onclick={() => askToRevoke(token)}>Revoke</button
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <dialog
    class="confirm-dialog"
    bind:this={revokeDialog}
    aria-labelledby="revoke-title"
    oncancel={(event) => {
      if (revoking) event.preventDefault();
    }}
    onclose={() => {
      if (!revoking) pendingRevoke = null;
    }}
  >
    <p class="eyebrow">Revoke credential</p>
    <h2 id="revoke-title">Stop using {pendingRevoke?.name ?? "this token"}?</h2>
    <p>Calls using this token will fail immediately. This action cannot be undone.</p>
    {#if revokeError !== null}<ErrorNotice error={revokeError} />{/if}
    <div class="button-row dialog-actions">
      <button type="button" disabled={revoking} onclick={() => (pendingRevoke = null)}>
        Cancel
      </button>
      <button class="danger-button" type="button" disabled={revoking} onclick={confirmRevoke}>
        {revoking ? "Revoking..." : "Revoke token"}
      </button>
    </div>
  </dialog>
</DashboardShell>
