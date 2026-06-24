import type { ToolMode } from "$lib/api";

export function requiresBroadConfirmation(mode: ToolMode | null) {
  return mode === "enabled" || mode === "disabled";
}

export function sourceModeImpact(toolCount: number) {
  const noun = toolCount === 1 ? "tool" : "tools";
  return `Up to ${toolCount} active ${noun} may inherit this source default. Tool overrides stay unchanged.`;
}

export function bulkActionLabel(mode: ToolMode | null, count: number) {
  const target = mode === null ? "Inherit" : modeName(mode);
  return `Apply ${target} to ${count} selected`;
}

export function broadConfirmationText(mode: ToolMode, count: number) {
  return `${modeName(mode)} ${count} selected ${count === 1 ? "tool" : "tools"}? This sets an explicit mode override on every selected tool.`;
}

export function modeName(mode: ToolMode) {
  if (mode === "enabled") return "Enabled";
  if (mode === "ask") return "Ask";
  return "Disabled";
}

export function inheritLabel(mode: ToolMode) {
  return `Inherit (currently ${modeName(mode)})`;
}

export function previewToolKey(preferredName: string, index: number) {
  return `${index}:${preferredName}`;
}
