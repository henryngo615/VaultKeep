/**
 * Client-side view of the sync server. Abstracted behind a Transport so the app
 * core can be tested against the in-process VaultService OR a real HTTP server
 * with identical behavior.
 */

export interface RemoteItem {
  id: string;
  ciphertext: string;
  version: number;
  updatedAt: string;
}

export type PushOutcome =
  | { status: "ok"; version: number }
  | { status: "conflict"; serverVersion: number; server: RemoteItem | null };

/** The minimal contract the desktop app needs from the server. */
export interface Transport {
  pull(since?: string): Promise<RemoteItem[]>;
  push(id: string, ciphertext: string, baseVersion: number | null): Promise<PushOutcome>;
}

/** HTTP transport for production (Bearer token auth). */
export class HttpTransport implements Transport {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly fetchImpl: typeof fetch = fetch
  ) {}

  private headers() {
    return {
      authorization: `Bearer ${this.token}`,
      "content-type": "application/json",
    };
  }

  async pull(since?: string): Promise<RemoteItem[]> {
    const u = new URL(`${this.baseUrl}/vault/items`);
    if (since) u.searchParams.set("since", since);
    const res = await this.fetchImpl(u, { headers: this.headers() });
    if (!res.ok) throw new Error(`pull failed: ${res.status}`);
    return (await res.json()).items as RemoteItem[];
  }

  async push(id: string, ciphertext: string, baseVersion: number | null): Promise<PushOutcome> {
    const res = await this.fetchImpl(`${this.baseUrl}/vault/items/${id}`, {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify({ ciphertext, baseVersion }),
    });
    return (await res.json()) as PushOutcome;
  }
}
