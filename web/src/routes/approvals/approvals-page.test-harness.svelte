<script lang="ts">
  import ApprovalsPage from "./+page.svelte";

  type PollEnvironment = {
    readonly schedule: (callback: () => void, delay: number) => number;
    readonly cancel: (handle: number) => void;
    readonly isVisible: () => boolean;
  };

  let {
    initialUrl,
    pollEnvironment,
  }: {
    initialUrl: string;
    pollEnvironment?: PollEnvironment;
  } = $props();

  let navigatedUrl = $state<URL | null>(null);
  let currentUrl = $derived(navigatedUrl ?? new URL(initialUrl));
  let approvalNavigation = $derived({ url: currentUrl, goto: navigate });

  function navigate(destination: string) {
    navigatedUrl = new URL(destination, currentUrl);
  }
</script>

<ApprovalsPage {approvalNavigation} approvalPollEnvironment={pollEnvironment} />
