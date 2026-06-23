<script lang="ts">
  import DashboardShell from "$lib/DashboardShell.svelte";
  import PlaceholderPanel from "$lib/PlaceholderPanel.svelte";
</script>

<DashboardShell
  title="Request logs"
  description="Understand what called what, without exposing secrets."
>
  <PlaceholderPanel
    label="04"
    title="Request history is not available yet"
    detail="Gateway request history and redaction controls will appear here when logging is connected. No sample requests are shown."
  />
</DashboardShell>
