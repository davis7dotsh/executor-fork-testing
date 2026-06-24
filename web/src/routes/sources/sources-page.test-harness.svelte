<script lang="ts">
  import { createAuthState, provideAuthState } from "$lib/auth.svelte";
  import SourcesPage from "./+page.svelte";

  provideAuthState(createAuthState());
</script>

<SourcesPage />
