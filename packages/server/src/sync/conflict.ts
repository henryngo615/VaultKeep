/**
 * Optimistic-concurrency conflict resolution for vault sync.
 *
 * Every vault item carries a monotonically-increasing `version`. When a client
 * pushes an update it sends the version it BASED its edit on. The server only
 * accepts the write if it's a clean successor; otherwise it reports a conflict
 * and the client re-merges. This prevents a stale device from silently
 * clobbering a newer change made on another device.
 *
 * This module is pure (no DB, no framework) so the rule is trivially testable.
 */

export interface StoredVersion {
  /** Version currently persisted on the server, or null if item is new. */
  current: number | null;
}

export interface PushAttempt {
  /** The version the client's edit was based on (the version it last saw). */
  baseVersion: number | null;
}

export type ResolveResult =
  | { kind: "create"; newVersion: number }
  | { kind: "update"; newVersion: number }
  | { kind: "conflict"; serverVersion: number };

/**
 * Decide what to do with an incoming push.
 *
 * - new item (no server version, client also has none) -> create at v1
 * - clean update (client based on the current server version) -> bump version
 * - anything else -> conflict; client must pull serverVersion and re-merge
 */
export function resolvePush(
  stored: StoredVersion,
  attempt: PushAttempt
): ResolveResult {
  if (stored.current === null) {
    // Server has never seen this id.
    if (attempt.baseVersion === null) return { kind: "create", newVersion: 1 };
    // Client thinks it's editing something the server doesn't have -> conflict
    // (e.g. item was deleted server-side). Let the client reconcile.
    return { kind: "conflict", serverVersion: 0 };
  }

  if (attempt.baseVersion === stored.current) {
    return { kind: "update", newVersion: stored.current + 1 };
  }

  // Client edited an older (or impossibly newer) version.
  return { kind: "conflict", serverVersion: stored.current };
}
