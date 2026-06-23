<script lang="ts">
  import DashboardShell from "$lib/DashboardShell.svelte";
  import PlaceholderPanel from "$lib/PlaceholderPanel.svelte";
</script>

<DashboardShell
  title="Sources"
  description="Connect MCP servers, OpenAPI services, and GraphQL endpoints."
>
  <PlaceholderPanel
    label="01"
    title="No sources connected"
    detail="Source connections are not available yet. No sample MCP, OpenAPI, or GraphQL connections are shown."
  />
</DashboardShell>
