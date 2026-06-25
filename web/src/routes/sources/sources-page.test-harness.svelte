<script lang="ts">
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import type { SourceCreateEnvironment } from "$lib/source-create-lifecycle";
  import SourcesPage from "./+page.svelte";

  let {
    initialOAuthUrl = null,
    initialOAuthState = {},
    onOAuthReplace,
    sourceCreateEnvironment,
  }: {
    initialOAuthUrl?: string | null;
    initialOAuthState?: App.PageState;
    onOAuthReplace?: (url: URL, state: App.PageState) => void;
    sourceCreateEnvironment?: SourceCreateEnvironment;
  } = $props();

  provideAuthState(createAuthState());

  let replacedOAuthUrl = $state<URL | null>(null);
  let replacedOAuthState = $state<App.PageState | null>(null);
  let oauthUrl = $derived(
    replacedOAuthUrl ?? (initialOAuthUrl === null ? null : new URL(initialOAuthUrl)),
  );
  let oauthState = $derived(replacedOAuthState ?? initialOAuthState);
  let oauthNavigation = $derived(
    oauthUrl === null
      ? undefined
      : { url: oauthUrl, state: oauthState, replaceState: replaceOAuthState },
  );

  function replaceOAuthState(url: URL, state: App.PageState) {
    replacedOAuthUrl = new URL(url);
    replacedOAuthState = state;
    onOAuthReplace?.(url, state);
  }
</script>

<SourcesPage {oauthNavigation} {sourceCreateEnvironment} />
