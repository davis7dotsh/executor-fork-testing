<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import type { ApiError } from "$lib/api";
  import type { Snippet } from "svelte";

  let {
    title,
    description,
    children,
    beforeSignOut,
    onSignOutFailed,
  }: {
    title: string;
    description: string;
    children: Snippet;
    beforeSignOut?: () => boolean;
    onSignOutFailed?: (error: ApiError) => void;
  } = $props();

  const auth = useAuthState();
  const navigation = [
    { href: "/sources", label: "Sources", marker: "01" },
    { href: "/tools", label: "Tools", marker: "02" },
    { href: "/approvals", label: "Approvals", marker: "03" },
    { href: "/logs", label: "Request logs", marker: "04" },
    { href: "/tokens", label: "API tokens", marker: "05" },
  ];
  let logoutBusy = $state(false);
  let logoutError = $state<ApiError | null>(null);
  let adminLabel = $derived(auth.username ?? "Administrator");

  function isActive(href: string) {
    return page.url.pathname === href || page.url.pathname.startsWith(`${href}/`);
  }

  async function logout() {
    if (beforeSignOut !== undefined && !beforeSignOut()) return;

    logoutBusy = true;
    logoutError = null;
    const result = await auth.signOut();
    if (!result.ok) {
      logoutError = result.error;
      onSignOutFailed?.(result.error);
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
          class:active={isActive(item.href)}
          href={item.href}
          aria-current={isActive(item.href) ? "page" : undefined}
        >
          <span class="nav-marker" aria-hidden="true">{item.marker}</span>
          <span class="nav-label">{item.label}</span>
        </a>
      {/each}
    </nav>

    <div class="instance-card">
      <div>
        <strong>Local instance</strong>
        <small>Self-hosted control plane</small>
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
