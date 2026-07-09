import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

export function jsonResult(data: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

export type WriteMode = {
  /** When true, preview only — no PUT calls. */
  dryRun: boolean;
  /** Set when a requested write was downgraded to dry-run. */
  notice?: string;
};

/**
 * Resolves whether a write tool should apply changes or preview only.
 * Missing BLACKDUCK_WRITE_ENABLED is safe: writes stay off unless explicitly enabled.
 */
export function resolveWriteMode(requestedDryRun: boolean | undefined, writeEnabled: boolean): WriteMode {
  const wantsApply = requestedDryRun === false;
  if (!wantsApply) {
    return { dryRun: true };
  }
  if (!writeEnabled) {
    return {
      dryRun: true,
      notice:
        "Writes are disabled (BLACKDUCK_WRITE_ENABLED is not set or is false). Ran as dry-run preview instead.",
    };
  }
  return { dryRun: false };
}

export function isWriteError(result: unknown): result is { error: string } {
  return typeof result === "object" && result !== null && "error" in result && typeof (result as { error: unknown }).error === "string";
}
