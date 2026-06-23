<script lang="ts">
  import { goto } from "$app/navigation";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import type { ApiError } from "$lib/api";
  import { consumeSetupToken } from "$lib/navigation";
  import { onMount } from "svelte";

  const auth = useAuthState();
  let setupToken = $state<string | null>(null);
  let fragmentRead = $state(false);
  let username = $state("admin");
  let password = $state("");
  let passwordConfirmation = $state("");
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let passwordsMatch = $derived(password === passwordConfirmation);
  let canSubmit = $derived(
    setupToken !== null &&
      username.trim() !== "" &&
      password.length >= 12 &&
      passwordsMatch &&
      !busy,
  );

  onMount(() => {
    setupToken = consumeSetupToken(new URL(window.location.href), (nextUrl) => {
      history.replaceState(history.state, "", nextUrl);
    });
    fragmentRead = true;
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit || setupToken === null) return;

    busy = true;
    error = null;
    const result = await auth.completeSetup({
      setupToken,
      username: username.trim(),
      password,
    });
    if (!result.ok) {
      error = result.error;
    } else if (auth.authenticated) {
      password = "";
      passwordConfirmation = "";
      void goto("/sources", { replaceState: true });
    }
    busy = false;
  }
</script>

<svelte:head>
  <title>Set up Executor</title>
</svelte:head>

<main class="centered-page setup-page">
  <section class="auth-card">
    <div class="auth-heading">
      <span class="brand-mark" aria-hidden="true">EX</span>
      <div>
        <p class="eyebrow">First boot</p>
        <h1>Make this instance yours.</h1>
      </div>
    </div>
    <p class="lede">
      Create the only administrator account. The one-time setup secret is removed from browser
      history as soon as this page opens.
    </p>

    {#if fragmentRead && setupToken === null}
      <div class="notice warning" role="alert">
        Open the exact setup link printed by <code>executor server</code>. Restarting an
        unconfigured instance prints a fresh one-time link.
      </div>
    {/if}

    <form onsubmit={submit}>
      <label>
        Administrator username
        <input bind:value={username} autocomplete="username" required maxlength="64" />
      </label>
      <label>
        Password
        <input
          bind:value={password}
          type="password"
          autocomplete="new-password"
          minlength="12"
          required
          aria-describedby="password-help"
        />
        <small id="password-help">Use at least 12 characters.</small>
      </label>
      <label>
        Confirm password
        <input
          bind:value={passwordConfirmation}
          type="password"
          autocomplete="new-password"
          minlength="12"
          required
          aria-invalid={passwordConfirmation !== "" && !passwordsMatch}
          aria-describedby={passwordConfirmation !== "" && !passwordsMatch
            ? "password-mismatch"
            : undefined}
        />
      </label>
      {#if passwordConfirmation !== "" && !passwordsMatch}
        <p id="password-mismatch" class="field-error" role="alert" aria-live="polite">
          The passwords do not match.
        </p>
      {/if}
      {#if error !== null}<ErrorNotice {error} />{/if}
      <button class="primary" type="submit" disabled={!canSubmit}>
        {busy ? "Creating administrator..." : "Create administrator"}
      </button>
    </form>
  </section>
</main>
