export async function copyText(text: string, fallbackField: HTMLInputElement) {
  if (navigator.clipboard?.writeText) {
    const copied = await navigator.clipboard.writeText(text).then(
      () => true,
      () => false,
    );
    if (copied) return true;
  }

  const previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;
  fallbackField.value = text;
  fallbackField.focus();
  fallbackField.select();

  // oxlint-disable-next-line executor/no-try-catch-or-throw -- boundary: legacy clipboard fallback must report failure and restore focus
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    previousFocus?.focus({ preventScroll: true });
  }
}
