<script lang="ts">
  import { page } from "$app/state";
  import { tick, untrack } from "svelte";
  import DashboardShell from "$lib/DashboardShell.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import { getRequestLog, listRequestLogs, type RequestLog, type RequestLogPage } from "$lib/api";
  import {
    beginIdentityResourceLoad,
    beginResourceLoad,
    createLatestRequest,
    emptyResource,
    settleResourceLoad,
    unexpectedRequestError,
  } from "$lib/catalog-state";
  import { logsListKey, logsUrl, parseLogsUrl } from "$lib/catalog-url";

  const auth = useAuthState();
  const listRequest = createLatestRequest();
  const detailRequest = createLatestRequest();
  let searchKey = $derived(page.url.search);
  let urlState = $derived(parseLogsUrl(new URLSearchParams(searchKey)));
  let listKey = $derived(logsListKey(urlState));
  let resource = $state(emptyResource<RequestLogPage>());
  let detail = $state(emptyResource<RequestLog>());
  let detailIdentity = $state<string | null>(null);
  let refreshKey = $state(0);
  let detailRefreshKey = $state(0);
  let detailReturnId = $state<string | null>(null);

  $effect(() => {
    const key = listKey;
    const requestKey = `${key}\u0000${refreshKey}`;
    const cursor = key || null;
    resource = beginResourceLoad(untrack(() => resource));
    return listRequest.start(
      async (signal) => ({ requestKey, result: await listRequestLogs(cursor, undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== `${listKey}\u0000${refreshKey}`) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        resource = settleResourceLoad(resource, result);
      },
      () => {
        resource = settleResourceLoad(resource, {
          ok: false,
          error: unexpectedRequestError(),
        });
      },
    );
  });

  $effect(() => {
    const requestId = urlState.request;
    const returnId = untrack(() => detailReturnId);
    void tick().then(() => {
      if (requestId !== null) {
        document.getElementById("request-detail-panel")?.focus();
      } else if (returnId !== null) {
        document.getElementById(`inspect-request-${returnId}`)?.focus();
        detailReturnId = null;
      }
    });
  });

  $effect(() => {
    const requestId = urlState.request;
    const requestKey = `${requestId ?? ""}\u0000${detailRefreshKey}`;
    if (requestId === null) {
      detail = { data: null, loading: false, error: null, stale: false };
      detailIdentity = null;
      return;
    }
    const started = beginIdentityResourceLoad(
      untrack(() => detail),
      untrack(() => detailIdentity),
      requestId,
    );
    detailIdentity = started.identity;
    detail = started.state;
    return detailRequest.start(
      async (signal) => ({ requestKey, result: await getRequestLog(requestId, undefined, signal) }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== `${urlState.request ?? ""}\u0000${detailRefreshKey}`) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        detail = settleResourceLoad(detail, result, { retainDataOnError: false });
      },
      () => {
        detail = settleResourceLoad(
          detail,
          { ok: false, error: unexpectedRequestError() },
          { retainDataOnError: false },
        );
      },
    );
  });

  function refreshLogs() {
    refreshKey += 1;
    if (urlState.request !== null) detailRefreshKey += 1;
  }

  function formatTime(timestamp: number) {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(
      timestamp * 1000,
    );
  }

  function outcomeLabel(outcome: RequestLog["outcome"]) {
    if (outcome === "pending_approval") return "Pending approval";
    return `${outcome[0].toUpperCase()}${outcome.slice(1)}`;
  }
</script>

<DashboardShell
  title="Request logs"
  description="Understand what called what, without exposing secrets."
>
  <section class="surface privacy-note">
    <div>
      <p class="eyebrow">Metadata only</p>
      <h2>Safe operational history</h2>
    </div>
    <p>
      Arguments, response bodies, headers, credentials, and tokens are never included in this view.
    </p>
  </section>

  {#if resource.stale && resource.error !== null}
    <div class="stale-notice" role="status">
      Showing the last loaded request page while Executor reconnects.
      <ErrorNotice error={resource.error} />
    </div>
  {:else if resource.error !== null}
    <section class="surface table-unavailable">
      <ErrorNotice error={resource.error} />
      <button type="button" onclick={refreshLogs}>Try again</button>
    </section>
  {/if}

  <section class="surface table-card" aria-busy={resource.loading}>
    <div class="section-heading">
      <div>
        <p class="eyebrow">Newest first</p>
        <h2>Gateway activity</h2>
      </div>
      <div class="button-row">
        {#if resource.loading}<span class="muted-status" role="status">Refreshing...</span>{/if}
        <button type="button" disabled={resource.loading} onclick={refreshLogs}>Refresh</button>
      </div>
    </div>
    {#if resource.data === null && resource.loading}
      <div class="loading-panel" aria-live="polite">Loading request logs...</div>
    {:else if resource.data !== null && resource.data.items.length === 0}
      <div class="table-empty">
        <p>No requests have been recorded on this page.</p>
        {#if urlState.cursor !== null}<a class="button-link" href="/logs"
            >Return to newest requests</a
          >{/if}
      </div>
    {:else if resource.data !== null}
      <div class="table-scroll">
        <table>
          <caption>Request metadata, newest first.</caption>
          <thead
            ><tr
              ><th scope="col">Request</th><th scope="col">Route</th><th scope="col">Outcome</th><th
                scope="col">Timing</th
              ><th scope="col">Details</th></tr
            ></thead
          >
          <tbody>
            {#each resource.data.items as log (log.requestId)}
              <tr>
                <td data-label="Request"
                  ><code>{log.requestId}</code><small
                    >{formatTime(log.createdAt)} · {log.surface}</small
                  ></td
                >
                <td data-label="Route"
                  ><code>{log.pathSnapshot ?? "Unknown path"}</code><small
                    >{log.sourceId ?? "Source unavailable"}</small
                  ></td
                >
                <td data-label="Outcome"
                  ><span
                    class:error={log.outcome === "failed" || log.outcome === "denied"}
                    class:pending={log.outcome === "pending_approval"}
                    class="outcome-pill">{outcomeLabel(log.outcome)}</span
                  >{#if log.errorCode !== null}<small><code>{log.errorCode}</code></small>{/if}</td
                >
                <td data-label="Timing">{log.durationMs} ms</td>
                <td data-label="Details"
                  ><a
                    id={`inspect-request-${log.requestId}`}
                    class="detail-link"
                    href={logsUrl(urlState, { request: log.requestId })}
                    onclick={() => (detailReturnId = log.requestId)}>Inspect</a
                  ></td
                >
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <nav class="pagination" aria-label="Request log pages">
        {#if urlState.cursor !== null}<a href="/logs">Newest</a>{:else}<span></span>{/if}
        <span>{resource.data.items.length} requests on this page</span>
        {#if resource.data.nextCursor !== null}
          <a href={logsUrl({ cursor: resource.data.nextCursor, request: null })}>Older</a>
        {/if}
      </nav>
    {/if}
  </section>

  {#if urlState.request !== null}
    <aside
      id="request-detail-panel"
      class="surface detail-panel"
      aria-labelledby="request-detail-title"
      aria-busy={detail.loading}
      tabindex="-1"
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">Request detail</p>
          <h2 id="request-detail-title">{detail.data?.requestId ?? "Loading..."}</h2>
        </div>
        <a class="button-link" href={logsUrl(urlState, { request: null })}>Close details</a>
      </div>
      {#if detail.error !== null}<div class="detail-body">
          <ErrorNotice error={detail.error} />
          <button type="button" onclick={() => (detailRefreshKey += 1)}>Retry details</button>
        </div>
      {:else if detail.loading && detail.data === null}<div class="loading-panel" role="status">
          Loading request detail...
        </div>
      {:else if detail.data !== null}
        <div class="detail-body">
          {#if detail.loading}<p class="muted-status" role="status">
              Refreshing request detail...
            </p>{/if}
          <dl class="detail-list">
            <div>
              <dt>Surface</dt>
              <dd>{detail.data.surface}</dd>
            </div>
            <div>
              <dt>Path</dt>
              <dd><code>{detail.data.pathSnapshot ?? "Unavailable"}</code></dd>
            </div>
            <div>
              <dt>Outcome</dt>
              <dd>{outcomeLabel(detail.data.outcome)}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>{detail.data.durationMs} ms</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>{formatTime(detail.data.createdAt)}</dd>
            </div>
            <div>
              <dt>Source ID</dt>
              <dd><code>{detail.data.sourceId ?? "Unavailable"}</code></dd>
            </div>
            <div>
              <dt>Tool ID</dt>
              <dd><code>{detail.data.toolId ?? "Unavailable"}</code></dd>
            </div>
            <div>
              <dt>API token ID</dt>
              <dd><code>{detail.data.actorApiTokenId ?? "Unavailable"}</code></dd>
            </div>
            <div>
              <dt>Error code</dt>
              <dd><code>{detail.data.errorCode ?? "None"}</code></dd>
            </div>
            <div>
              <dt>Approval ID</dt>
              <dd><code>{detail.data.approvalId ?? "None"}</code></dd>
            </div>
          </dl>
        </div>
      {/if}
    </aside>
  {/if}
</DashboardShell>
