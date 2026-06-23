<script lang="ts">
  import DashboardShell from "$lib/DashboardShell.svelte";
  import PlaceholderPanel from "$lib/PlaceholderPanel.svelte";
</script>

<DashboardShell
  title="Approvals"
  description="Pause sensitive calls and resume them after a deliberate decision."
>
  <PlaceholderPanel
    label="03"
    title="Approvals are not available yet"
    detail="Approval rules and pending decisions will appear here when interactive execution is available. No sample requests are shown."
  />
</DashboardShell>
