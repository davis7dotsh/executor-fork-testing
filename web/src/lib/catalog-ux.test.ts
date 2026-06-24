import { describe, expect, it } from "@effect/vitest";
import {
  broadConfirmationText,
  bulkActionLabel,
  inheritLabel,
  previewToolKey,
  requiresBroadConfirmation,
  sourceModeImpact,
} from "./catalog-ux";

describe("catalog mode UX", () => {
  it("requires confirmation for broad enable and disable changes", () => {
    expect(requiresBroadConfirmation("enabled")).toBe(true);
    expect(requiresBroadConfirmation("disabled")).toBe(true);
    expect(requiresBroadConfirmation("ask")).toBe(false);
    expect(requiresBroadConfirmation(null)).toBe(false);
  });

  it("names bulk actions with their target and selected count", () => {
    expect(bulkActionLabel("ask", 3)).toBe("Apply Ask to 3 selected");
    expect(bulkActionLabel(null, 1)).toBe("Apply Inherit to 1 selected");
    expect(broadConfirmationText("disabled", 2)).toBe(
      "Disabled 2 selected tools? This sets an explicit mode override on every selected tool.",
    );
  });

  it("explains inherited state and conservative source impact", () => {
    expect(inheritLabel("enabled")).toBe("Inherit (currently Enabled)");
    expect(sourceModeImpact(1)).toContain("Up to 1 active tool");
    expect(sourceModeImpact(12)).toContain("Up to 12 active tools");
    expect(sourceModeImpact(12)).toContain("Tool overrides stay unchanged");
  });

  it("keeps legal duplicate preview names collision-safe", () => {
    expect(previewToolKey("duplicate", 0)).not.toBe(previewToolKey("duplicate", 1));
  });
});
