<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import type { ApiError } from "$lib/api";
  import { safeReturnTo } from "$lib/navigation";

  const auth = useAuthState();
  let username = $state("admin");
  let password = $state("");
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let returnTo = $derived(
    safeReturnTo(page.url.searchParams.get("returnTo"), page.url.origin) ?? "/sources",
  );
  let canSubmit = $derived(username.trim() !== "" && password !== "" && !busy);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit) return;

    busy = true;
    error = null;
    const result = await auth.signIn({ username: username.trim(), password });
    if (!result.ok) {
      error = result.error;
    } else if (auth.authenticated) {
      password = "";
      void goto(returnTo, { replaceState: true });
    }
    busy = false;
  }
</script>

<svelte:head>
  <title>Sign in | Executor</title>
</svelte:head>

<main class="centered-page">
  <section class="auth-card">
    <div class="auth-heading">
      <span class="brand-mark" aria-hidden="true">EX</span>
      <div>
        <p class="eyebrow">Administrator</p>
        <h1>Open your gateway.</h1>
      </div>
    </div>
    <p class="lede">The dashboard session controls configuration. API tokens only reach tools.</p>

    {#if auth.notice !== null}
      <div class="notice warning" role="status">
        {auth.notice}
        <button class="text-button" type="button" onclick={auth.clearNotice}>Dismiss</button>
      </div>
    {/if}

    <form onsubmit={submit}>
      <label>
        Username
        <input bind:value={username} autocomplete="username" required />
      </label>
      <label>
        Password
        <input bind:value={password} type="password" autocomplete="current-password" required />
      </label>
      {#if error !== null}<ErrorNotice {error} />{/if}
      <button class="primary" type="submit" disabled={!canSubmit}>
        {busy ? "Signing in..." : "Sign in"}
      </button>
    </form>
  </section>
</main>
