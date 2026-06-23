<script lang="ts">
  import "../styles.css";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import favicon from "$lib/assets/favicon.svg";
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { isProtectedPath, routeDestination } from "$lib/navigation";
  import { onMount, type Snippet } from "svelte";

  let { children }: { children: Snippet } = $props();

  const auth = createAuthState();
  provideAuthState(auth);

  let pathname = $derived(page.url.pathname);
  let protectedPage = $derived(isProtectedPath(pathname));
  let authorizedPath = $state<string | null>(null);
  let canRender = $derived(
    !protectedPage || (auth.phase === "ready" && auth.authenticated) || authorizedPath === pathname,
  );

  onMount(() => {
    const controller = new AbortController();
    void auth.refresh(controller.signal);

    return () => {
      controller.abort();
      auth.dispose();
    };
  });

  $effect(() => {
    if (auth.phase !== "ready") return;

    if (!protectedPage) {
      authorizedPath = null;
    } else if (auth.authenticated) {
      authorizedPath = pathname;
    }

    const destination = routeDestination({
      pathname: page.url.pathname,
      search: page.url.search,
      hash: page.url.hash,
      origin: page.url.origin,
      setupRequired: auth.setupRequired,
      authenticated: auth.authenticated,
    });
    if (destination !== null) void goto(destination, { replaceState: true });
  });
</script>

<svelte:head>
  <title>Executor</title>
  <link rel="icon" href={favicon} />
  <meta
    name="description"
    content="A local gateway for MCP servers, OpenAPI services, and GraphQL endpoints."
  />
</svelte:head>

{#if auth.phase === "error" && auth.error !== null}
  <main class="centered-page" aria-live="polite">
    <section class="auth-card compact">
      <span class="brand-mark" aria-hidden="true">EX</span>
      <div>
        <ErrorNotice error={auth.error} />
        <button type="button" onclick={() => auth.refresh()}>Try again</button>
      </div>
    </section>
  </main>
{:else if canRender}
  {@render children()}
{:else}
  <main class="centered-page" aria-live="polite">
    <section class="auth-card compact">
      <span class="brand-mark" aria-hidden="true">EX</span>
      <p>Checking your Executor session...</p>
    </section>
  </main>
{/if}
