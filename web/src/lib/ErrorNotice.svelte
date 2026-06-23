<script lang="ts">
  import type { ApiError } from "$lib/api";

  let { error }: { error: ApiError } = $props();
  let message = $derived(error.displayMessage);
  let requestId = $derived(error.requestId);
</script>

<div class="notice error" role="alert">
  <strong>{message}</strong>
  {#if requestId !== null}
    <small>Request reference: <code>{requestId}</code></small>
  {/if}
</div>
