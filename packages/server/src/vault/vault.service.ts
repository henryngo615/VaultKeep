import { resolvePush } from "../sync/conflict.js";
import type { StoredItem, VaultRepository } from "./vault.repository.js";

export interface PushRequest {
  id: string;
  ciphertext: string;
  /** Version the client based this edit on (null for a brand-new item). */
  baseVersion: number | null;
}

export type PushResponse =
  | { status: "ok"; version: number }
  | { status: "conflict"; serverVersion: number; server: StoredItem | null };

/**
 * The framework-free sync engine. NestJS controllers call straight into this.
 * It enforces zero-knowledge (ciphertext in/out only) and optimistic
 * concurrency (no silent overwrites of newer data).
 */
export class VaultService {
  constructor(private readonly repo: VaultRepository) {}

  /** Pull everything changed since the given ISO timestamp. */
  async pull(userId: string, since?: string): Promise<StoredItem[]> {
    return this.repo.listSince(userId, since);
  }

  /** Push one encrypted item with optimistic-concurrency checking. */
  async push(userId: string, req: PushRequest): Promise<PushResponse> {
    const existing = await this.repo.get(userId, req.id);
    const decision = resolvePush(
      { current: existing?.version ?? null },
      { baseVersion: req.baseVersion }
    );

    if (decision.kind === "conflict") {
      return {
        status: "conflict",
        serverVersion: decision.serverVersion,
        server: existing,
      };
    }

    const item: StoredItem = {
      id: req.id,
      userId,
      ciphertext: req.ciphertext,
      version: decision.newVersion,
      updatedAt: new Date().toISOString(),
    };
    await this.repo.put(item);
    return { status: "ok", version: decision.newVersion };
  }

  async delete(userId: string, id: string): Promise<void> {
    await this.repo.remove(userId, id);
  }
}
