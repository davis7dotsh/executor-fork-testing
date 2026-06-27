<script lang="ts">
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import ToolsPage from "./+page.svelte";

  provideAuthState(createAuthState());
</script>

<ToolsPage />
