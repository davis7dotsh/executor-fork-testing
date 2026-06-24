<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { onMount, tick, untrack } from "svelte";
  import DashboardShell from "$lib/DashboardShell.svelte";
  import ErrorNotice from "$lib/ErrorNotice.svelte";
  import { useAuthState } from "$lib/auth.svelte";
  import {
    decideApproval,
    getApproval,
    listApprovals,
    type ApprovalDecision,
    type ApprovalDetail,
    type ApprovalPage,
  } from "$lib/api";
  import {
    approvalCountdown,
    approvalDecisionCopy,
    approvalStatuses,
    approvalStatusLabel,
    canDecideApproval,
    createApprovalPoller,
    decisionResultScope,
    focusTargetAfterDecision,
  } from "$lib/approval-state";
  import {
    approvalsListKey,
    approvalsUrl,
    parseApprovalsUrl,
    type ApprovalStatusFilter,
  } from "$lib/approval-url";
  import {
    beginIdentityResourceLoad,
    beginResourceLoad,
    createLatestRequest,
    emptyResource,
    settleResourceLoad,
    unexpectedRequestError,
  } from "$lib/catalog-state";

  const auth = useAuthState();
  const listRequest = createLatestRequest();
  const detailRequest = createLatestRequest();
  let searchKey = $derived(page.url.search);
  let urlState = $derived(parseApprovalsUrl(new URLSearchParams(searchKey)));
  let listKey = $derived(approvalsListKey(urlState));
  let resource = $state(emptyResource<ApprovalPage>());
  let detail = $state(emptyResource<ApprovalDetail>());
  let detailIdentity = $state<string | null>(null);
  let refreshKey = $state(0);
  let detailRefreshKey = $state(0);
  let detailReturnId = $state<string | null>(null);
  let now = $state(Date.now());
  let confirming = $state<ApprovalDecision | null>(null);
  let decisionById = $state<Record<string, ApprovalDecision | undefined>>({});
  let decisionError = $state<import("$lib/api").ApiError | null>(null);
  let announcement = $state("");
  let disposed = false;
  let decisionReadOnly = $derived(
    resource.loading || resource.stale || detail.loading || detail.stale,
  );

  onMount(() => {
    return () => {
      disposed = true;
    };
  });

  $effect(() => {
    const interval = window.setInterval(() => {
      now = Date.now();
      if (confirming !== null && detail.data !== null && !canDecideApproval(detail.data, now)) {
        confirming = null;
        announcement = "The approval deadline passed. Refresh to see the recorded outcome.";
        void tick().then(() => document.getElementById("approval-detail-panel")?.focus());
      }
    }, 1_000);
    return () => window.clearInterval(interval);
  });

  $effect(() => {
    return createApprovalPoller({
      schedule: (callback, delay) => window.setTimeout(callback, delay),
      cancel: (handle) => window.clearTimeout(handle),
      isVisible: () => document.visibilityState === "visible",
      isListLoading: () => resource.loading,
      hasDetail: () => urlState.approval !== null,
      isDetailLoading: () => detail.loading,
      refreshList: () => (refreshKey += 1),
      refreshDetail: () => (detailRefreshKey += 1),
    });
  });

  $effect(() => {
    const key = listKey;
    const requestKey = `${key}\u0000${refreshKey}`;
    const status = urlState.status === "all" ? null : urlState.status;
    const cursor = urlState.cursor;
    resource = beginResourceLoad(untrack(() => resource));
    return listRequest.start(
      async (signal) => ({
        requestKey,
        result: await listApprovals({ status, cursor, limit: 50 }, undefined, signal),
      }),
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
    const approvalId = urlState.approval;
    const returnId = untrack(() => detailReturnId);
    void tick().then(() => {
      if (approvalId !== null) {
        document.getElementById("approval-detail-panel")?.focus();
      } else if (returnId !== null) {
        (
          document.getElementById(`inspect-approval-${returnId}`) ??
          document.getElementById("approvals-heading")
        )?.focus();
        detailReturnId = null;
      }
    });
  });

  $effect(() => {
    const approvalId = urlState.approval;
    const requestKey = `${approvalId ?? ""}\u0000${detailRefreshKey}`;
    if (approvalId === null) {
      confirming = null;
      decisionError = null;
      detail = { data: null, loading: false, error: null, stale: false };
      detailIdentity = null;
      return;
    }
    const identityChanged = untrack(() => detailIdentity) !== approvalId;
    if (identityChanged) {
      confirming = null;
      decisionError = null;
    }
    const started = beginIdentityResourceLoad(
      untrack(() => detail),
      untrack(() => detailIdentity),
      approvalId,
    );
    detailIdentity = started.identity;
    detail = started.state;
    return detailRequest.start(
      async (signal) => ({
        requestKey,
        result: await getApproval(approvalId, undefined, signal),
      }),
      ({ requestKey: completedKey, result }) => {
        if (completedKey !== `${urlState.approval ?? ""}\u0000${detailRefreshKey}`) return;
        if (!result.ok && auth.recoverFromApiError(result.error)) return;
        const decisionHadFocus =
          document.getElementById("approval-decision-region")?.contains(document.activeElement) ??
          false;
        if (result.ok) decisionError = null;
        detail = settleResourceLoad(detail, result, { retainDataOnError: false });
        if (decisionHadFocus && (!result.ok || !canDecideApproval(result.value, Date.now()))) {
          announcement = result.ok
            ? `This approval is now ${approvalStatusLabel(result.value.status)}.`
            : "The latest approval detail could not be loaded.";
          void tick().then(() => {
            const target = result.ok
              ? document.getElementById("approval-detail-panel")
              : document.getElementById("retry-approval-detail");
            target?.focus();
          });
        }
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

  function refreshApprovals() {
    refreshKey += 1;
    if (urlState.approval !== null) detailRefreshKey += 1;
  }

  async function beginConfirmation(decision: ApprovalDecision) {
    confirming = decision;
    await tick();
    document.getElementById("confirm-approval-decision")?.focus();
  }

  async function cancelConfirmation() {
    const decision = confirming;
    confirming = null;
    await tick();
    document.getElementById(decision === "deny" ? "start-deny" : "start-approve")?.focus();
  }

  function filterChanged(event: Event) {
    const select = event.currentTarget;
    if (!(select instanceof HTMLSelectElement)) return;
    const status = select.value as ApprovalStatusFilter;
    void goto(approvalsUrl(urlState, { status, cursor: null, approval: null }));
  }

  async function submitDecision(approval: ApprovalDetail, decision: ApprovalDecision) {
    if (decisionById[approval.id] !== undefined || decisionReadOnly) return;
    if (!canDecideApproval(approval, Date.now())) {
      confirming = null;
      announcement = "The approval deadline passed. Reloaded it for review.";
      refreshKey += 1;
      detailRefreshKey += 1;
      await tick();
      document.getElementById("approval-detail-panel")?.focus();
      return;
    }
    const submittedListKey = listKey;
    const submittedStatus = urlState.status;
    const submittedItems = resource.data?.items ?? [];
    decisionById[approval.id] = decision;
    decisionError = null;
    const toolLabel = approval.toolDisplayName ?? approval.path;
    announcement = `${decision === "approve" ? "Approving" : "Denying"} ${toolLabel}...`;
    const result = await decideApproval(approval.id, decision, approval.revision);
    delete decisionById[approval.id];
    if (disposed) return;

    if (!result.ok) {
      if (auth.recoverFromApiError(result.error)) return;
      if (urlState.approval !== approval.id) return;
      decisionError = result.error;
      confirming = null;
      if (result.error.status === 409 || result.error.status === 410) {
        announcement =
          result.error.status === 409
            ? "This approval changed before your decision. Reloaded it for review."
            : "The approval deadline passed. Reloaded it for review.";
        refreshKey += 1;
        detailRefreshKey += 1;
        await tick();
        document.getElementById("approval-detail-panel")?.focus();
      } else {
        announcement = `The ${decision} decision was not saved.`;
        await tick();
        document.getElementById(decision === "deny" ? "start-deny" : "start-approve")?.focus();
      }
      return;
    }

    const scope = decisionResultScope({
      submittedApprovalId: approval.id,
      submittedListKey,
      currentApprovalId: urlState.approval,
      currentListKey: listKey,
    });
    if (scope.sameList && resource.data !== null) {
      const items =
        submittedStatus === "pending"
          ? resource.data.items.filter((item) => item.id !== approval.id)
          : resource.data.items.map((item) => (item.id === approval.id ? result.value : item));
      resource = {
        data: { ...resource.data, items },
        loading: false,
        error: null,
        stale: false,
      };
    }
    refreshKey += 1;

    if (!scope.sameDetail) return;
    announcement = `${toolLabel} was ${decision === "approve" ? "approved" : "denied"}.`;
    confirming = null;
    detail = settleResourceLoad(detail, result);

    if (scope.sameList && submittedStatus === "pending") {
      const target = focusTargetAfterDecision(submittedItems, approval.id);
      await goto(approvalsUrl(urlState, { approval: null }));
      await tick();
      document.getElementById(target)?.focus();
    } else {
      detailRefreshKey += 1;
    }
  }

  function formatTime(timestamp: number) {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(
      timestamp * 1000,
    );
  }

  function formatAge(createdAt: number) {
    const seconds = Math.max(0, Math.floor(now / 1000) - createdAt);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3_600)}h ago`;
  }

  function provenanceLabel(provenance: ApprovalDetail["provenance"]) {
    if (provenance === "tool_override") return "Tool override";
    if (provenance === "source_override") return "Source default";
    return "Tool default";
  }

  function closeDetail() {
    detailReturnId = detail.data?.id ?? urlState.approval;
    void goto(approvalsUrl(urlState, { approval: null }));
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (event.key !== "Escape" || urlState.approval === null) return;
    event.preventDefault();
    closeDetail();
  }
</script>

<svelte:window onkeydown={handleWindowKeydown} />

<DashboardShell title="Approvals" description="Review each sensitive tool call before it can run.">
  <p class="visually-hidden" aria-live="polite">{announcement}</p>

  <section class="surface approval-explainer">
    <div>
      <p class="eyebrow">One request at a time</p>
      <h2>Approval is exact and single-use</h2>
    </div>
    <p>
      Approving permits only this invocation. The argument preview is structural and redacted;
      hidden original values are what Executor will run. A tool, credential, or policy change makes
      the request stale instead of silently applying your decision elsewhere.
    </p>
  </section>

  <section class="surface approval-filters" aria-labelledby="approvals-heading">
    <div>
      <p class="eyebrow">Decision queue</p>
      <h2 id="approvals-heading" tabindex="-1">Approval requests</h2>
    </div>
    <label>
      Status
      <select value={urlState.status} onchange={filterChanged}>
        <option value="pending">Pending</option>
        <option value="all">All statuses</option>
        {#each approvalStatuses.filter((status) => status !== "pending") as status}
          <option value={status}>{approvalStatusLabel(status)}</option>
        {/each}
      </select>
    </label>
    <div class="button-row">
      {#if resource.loading}<span class="muted-status" role="status">Refreshing...</span>{/if}
      <button type="button" disabled={resource.loading} onclick={refreshApprovals}>Refresh</button>
    </div>
  </section>

  {#if resource.stale && resource.error !== null}
    <div class="stale-notice" role="status">
      Showing the last loaded approval page read-only while Executor reconnects.
      <ErrorNotice error={resource.error} />
    </div>
  {:else if resource.error !== null}
    <section class="surface table-unavailable">
      <ErrorNotice error={resource.error} />
      <button type="button" onclick={refreshApprovals}>Try again</button>
    </section>
  {/if}

  <section class="surface table-card" aria-busy={resource.loading}>
    {#if resource.data === null && resource.loading}
      <div class="loading-panel" aria-live="polite">Loading approvals...</div>
    {:else if resource.data !== null && resource.data.items.length === 0}
      <div class="table-empty">
        <p>
          {urlState.status === "pending"
            ? "No tool calls are waiting for approval."
            : "No approvals match this status on this page."}
        </p>
        {#if urlState.cursor !== null || urlState.status !== "pending"}
          <a class="button-link empty-recovery" href="/approvals">Return to pending approvals</a>
        {/if}
      </div>
    {:else if resource.data !== null}
      <div class="approval-list">
        {#each resource.data.items as approval (approval.id)}
          <article class="approval-row">
            <div class="approval-row-main">
              <div>
                <span
                  class:pending={approval.status === "pending"}
                  class:active={approval.status === "approved" || approval.status === "executing"}
                  class:success={approval.status === "succeeded"}
                  class:warning={["denied", "canceled", "expired", "stale"].includes(
                    approval.status,
                  )}
                  class:error={approval.status === "failed" || approval.status === "interrupted"}
                  class="outcome-pill"
                >
                  {approvalStatusLabel(approval.status)}
                </span>
                <h3>{approval.toolDisplayName ?? approval.path}</h3>
                <code>{approval.path}</code>
              </div>
              <div class="approval-timing">
                <strong>{formatAge(approval.createdAt)}</strong>
                <small>
                  {approval.status === "pending"
                    ? approvalCountdown(approval.expiresAt, now)
                    : `Updated ${formatAge(approval.updatedAt)}`}
                </small>
              </div>
            </div>
            <dl class="approval-summary">
              <div>
                <dt>Source</dt>
                <dd>{approval.sourceDisplayName ?? "Unavailable source"}</dd>
              </div>
              <div>
                <dt>Caller</dt>
                <dd>{approval.actorLabel}</dd>
                <small>{approval.surface}</small>
              </div>
              <div>
                <dt>Ask rule</dt>
                <dd>{provenanceLabel(approval.provenance)}</dd>
              </div>
            </dl>
            <a
              id={`inspect-approval-${approval.id}`}
              class="detail-link"
              href={approvalsUrl(urlState, { approval: approval.id })}>Review request</a
            >
          </article>
        {/each}
      </div>
      <nav class="pagination" aria-label="Approval pages">
        {#if urlState.cursor !== null}
          <a href={approvalsUrl(urlState, { cursor: null, approval: null })}>Newest</a>
        {:else}<span></span>{/if}
        <span>{resource.data.items.length} approvals on this page</span>
        {#if resource.data.nextCursor !== null}
          <a href={approvalsUrl(urlState, { cursor: resource.data.nextCursor, approval: null })}
            >Older</a
          >
        {/if}
      </nav>
    {/if}
  </section>

  {#if urlState.approval !== null}
    <aside
      id="approval-detail-panel"
      class="surface detail-panel approval-detail"
      aria-labelledby="approval-detail-title"
      aria-busy={detail.loading}
      tabindex="-1"
    >
      <div class="section-heading">
        <div>
          <p class="eyebrow">Approval detail</p>
          <h2 id="approval-detail-title">
            {detail.data?.toolDisplayName ?? detail.data?.path ?? "Loading..."}
          </h2>
        </div>
        <a
          class="button-link"
          href={approvalsUrl(urlState, { approval: null })}
          onclick={(event) => {
            event.preventDefault();
            closeDetail();
          }}>Close details</a
        >
      </div>
      {#if detail.error !== null}
        <div class="detail-body">
          <ErrorNotice error={detail.error} />
          <button id="retry-approval-detail" type="button" onclick={() => (detailRefreshKey += 1)}
            >Retry details</button
          >
        </div>
      {:else if detail.loading && detail.data === null}
        <div class="loading-panel" role="status">Loading approval detail...</div>
      {:else if detail.data !== null}
        <div class="detail-body">
          {#if detail.loading}<p class="muted-status" role="status">
              Refreshing approval detail...
            </p>{/if}
          <div class="approval-detail-heading">
            <span
              class:pending={detail.data.status === "pending"}
              class:active={detail.data.status === "approved" || detail.data.status === "executing"}
              class:success={detail.data.status === "succeeded"}
              class:warning={["denied", "canceled", "expired", "stale"].includes(
                detail.data.status,
              )}
              class:error={detail.data.status === "failed" || detail.data.status === "interrupted"}
              class="outcome-pill"
            >
              {approvalStatusLabel(detail.data.status)}
            </span>
            <div>
              <code>{detail.data.path}</code>
              <p>{detail.data.sourceDisplayName ?? "Unavailable source"}</p>
            </div>
          </div>
          <dl class="detail-list">
            <div>
              <dt>Requested</dt>
              <dd>{formatTime(detail.data.createdAt)}</dd>
            </div>
            <div>
              <dt>Approval deadline</dt>
              <dd>
                {detail.data.status === "pending"
                  ? approvalCountdown(detail.data.expiresAt, now)
                  : "No longer pending"}
              </dd>
              <small>{formatTime(detail.data.expiresAt)}</small>
            </div>
            <div>
              <dt>Caller</dt>
              <dd>{detail.data.actorLabel}</dd>
              <small>{detail.data.actorKind.replace("_", " ")}</small>
            </div>
            <div>
              <dt>Actor ID</dt>
              <dd><code>{detail.data.actorId}</code></dd>
            </div>
            {#if detail.data.actorApiTokenId !== null}
              <div>
                <dt>API token ID</dt>
                <dd><code>{detail.data.actorApiTokenId}</code></dd>
              </div>
            {/if}
            <div>
              <dt>Surface</dt>
              <dd>{detail.data.surface}</dd>
            </div>
            <div>
              <dt>Effective behavior</dt>
              <dd>Ask, {provenanceLabel(detail.data.provenance)}</dd>
            </div>
            <div>
              <dt>Revision</dt>
              <dd>{detail.data.revision}</dd>
            </div>
            {#if detail.data.failureCode !== null}
              <div>
                <dt>Outcome code</dt>
                <dd><code>{detail.data.failureCode}</code></dd>
              </div>
            {/if}
          </dl>

          <div class="approval-arguments">
            <div>
              <h3>Structural, redacted argument preview</h3>
              <p>
                Some original values are hidden. If approved, Executor runs the stored original
                arguments, not the placeholder text shown here.
              </p>
            </div>
            <pre>{JSON.stringify(detail.data.redactedArguments, null, 2)}</pre>
          </div>

          {#if canDecideApproval(detail.data, now)}
            <div id="approval-decision-region" class="approval-decision">
              {#if decisionReadOnly}
                <p class="muted-status" role="status">
                  Decisions are paused while the latest approval state loads.
                </p>
              {/if}
              {#if confirming === null}
                <p>
                  Review the tool and structural preview. Hidden original values will execute, and
                  approval may trigger a side effect in
                  {detail.data.sourceDisplayName ?? "the connected source"}.
                </p>
                <div class="button-row">
                  <button
                    id="start-approve"
                    class="primary"
                    type="button"
                    disabled={decisionReadOnly || decisionById[detail.data.id] !== undefined}
                    onclick={() => beginConfirmation("approve")}>Approve once</button
                  >
                  <button
                    id="start-deny"
                    class="danger-link"
                    type="button"
                    disabled={decisionReadOnly || decisionById[detail.data.id] !== undefined}
                    onclick={() => beginConfirmation("deny")}>Deny</button
                  >
                </div>
              {:else}
                <div class="approval-confirm" role="group" aria-labelledby="approval-confirm-title">
                  <h3 id="approval-confirm-title">
                    {confirming === "approve" ? "Confirm approval" : "Confirm denial"}
                  </h3>
                  <p>{approvalDecisionCopy(detail.data, confirming)}</p>
                  <div class="button-row">
                    <button
                      id="confirm-approval-decision"
                      class:primary={confirming === "approve"}
                      class:danger-button={confirming === "deny"}
                      type="button"
                      disabled={decisionReadOnly || decisionById[detail.data.id] !== undefined}
                      onclick={() => submitDecision(detail.data!, confirming!)}
                    >
                      {decisionById[detail.data.id] !== undefined
                        ? "Saving decision..."
                        : confirming === "approve"
                          ? "Yes, approve once"
                          : "Yes, deny request"}
                    </button>
                    <button
                      type="button"
                      disabled={decisionById[detail.data.id] !== undefined}
                      onclick={cancelConfirmation}>Keep reviewing</button
                    >
                  </div>
                </div>
              {/if}
            </div>
          {:else}
            <div class="notice">
              <strong>This request can no longer be decided.</strong>
              <small>
                {detail.data.status === "pending"
                  ? "Its approval deadline has passed. Refresh to see the recorded outcome."
                  : `Its recorded status is ${approvalStatusLabel(detail.data.status)}.`}
              </small>
            </div>
          {/if}

          {#if decisionError !== null}<ErrorNotice error={decisionError} />{/if}
        </div>
      {/if}
    </aside>
  {/if}
</DashboardShell>
