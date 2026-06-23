<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import type { ApiError } from "$lib/api";
  import type { Snippet } from "svelte";

  let { title, description, children }: { title: string; description: string; children: Snippet } =
    $props();

  const auth = useAuthState();
  const navigation = [
    { href: "/sources", label: "Sources", marker: "01" },
    { href: "/tools", label: "Tools", marker: "02" },
    { href: "/approvals", label: "Approvals", marker: "03", count: "--" },
    { href: "/logs", label: "Request logs", marker: "04" },
    { href: "/tokens", label: "API tokens", marker: "05" },
  ];
  let logoutBusy = $state(false);
  let logoutError = $state<ApiError | null>(null);
  let adminLabel = $derived(auth.username ?? "Administrator");

  async function logout() {
    logoutBusy = true;
    logoutError = null;
    const result = await auth.signOut();
    if (!result.ok) {
      logoutError = result.error;
    } else {
      void goto("/login", { replaceState: true });
    }
    logoutBusy = false;
  }
</script>

<svelte:head>
  <title>{title} | Executor</title>
</svelte:head>

<a class="skip-link" href="#main-content">Skip to main content</a>

<div class="app-frame">
  <aside class="sidebar">
    <a class="brand" href="/sources" aria-label="Executor home">
      <span class="brand-mark" aria-hidden="true">EX</span>
      <span>
        <strong>Executor</strong>
        <small>Local gateway</small>
      </span>
    </a>

    <nav aria-label="Dashboard">
      {#each navigation as item}
        <a
          class:active={page.url.pathname === item.href}
          href={item.href}
          aria-current={page.url.pathname === item.href ? "page" : undefined}
        >
          <span class="nav-marker">{item.marker}</span>
          <span class="nav-label">{item.label}</span>
          {#if item.count !== undefined}
            <span class="nav-count" aria-label="Approval count unavailable">
              <span aria-hidden="true">{item.count}</span>
            </span>
          {/if}
        </a>
      {/each}
    </nav>

    <div class="instance-card">
      <span class="status-dot" aria-hidden="true"></span>
      <div>
        <strong>Local instance</strong>
        <small>Connected over this origin</small>
      </div>
    </div>
  </aside>

  <main id="main-content" tabindex="-1">
    <header class="page-header">
      <div>
        <p class="eyebrow">Control plane</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div class="admin-actions">
        <span>Signed in as <strong>{adminLabel}</strong></span>
        <button type="button" onclick={logout} disabled={logoutBusy}>
          {logoutBusy ? "Signing out..." : "Sign out"}
        </button>
      </div>
    </header>
    {#if logoutError !== null}
      <div class="shell-notice"><ErrorNotice error={logoutError} /></div>
    {/if}
    <section class="page-content">{@render children()}</section>
  </main>
</div>
