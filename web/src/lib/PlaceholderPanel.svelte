<script lang="ts">
  let { label, title, detail }: { label: string; title: string; detail: string } = $props();
</script>

<div class="placeholder-grid">
  <article class="surface empty-state">
    <span class="number-chip">{label}</span>
    <h2>{title}</h2>
    <p>{detail}</p>
    <p class="availability">Not available yet</p>
  </article>
  <aside class="surface scope-card">
    <p class="eyebrow">Current status</p>
    <h3>No sample data</h3>
    <p>
      Executor keeps unavailable workflows empty, so anything shown in this dashboard represents
      real instance data.
    </p>
  </aside>
</div>
