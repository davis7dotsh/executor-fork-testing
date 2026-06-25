<script lang="ts">
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import type { TokenCreateEnvironment } from "$lib/token-create-lifecycle";
  import TokensPage from "./+page.svelte";

  let { tokenCreateEnvironment }: { tokenCreateEnvironment?: TokenCreateEnvironment } = $props();

  const auth = createAuthState();
  Object.defineProperty(auth, "authenticated", { get: () => true });
  provideAuthState(auth);
</script>

<TokensPage {tokenCreateEnvironment} />
