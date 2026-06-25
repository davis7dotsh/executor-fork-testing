<script lang="ts">
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import LogsPage from "./+page.svelte";

  let { search = "" }: { search?: string } = $props();

  provideAuthState(createAuthState());
</script>

<LogsPage {search} />
