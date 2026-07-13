import { execSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * A live Postgres for integration tests. If DATABASE_URL is set (e.g. the
 * docker-compose database), it is used as-is. Otherwise a real, throwaway
 * Postgres server is booted via embedded-postgres — no Docker or system
 * install required.
 */
export interface LiveDb {
  url: string;
  stop(): Promise<void>;
}

const SERVER_ROOT = fileURLToPath(new URL("../..", import.meta.url));

export async function startLivePostgres(): Promise<LiveDb> {
  if (process.env.DATABASE_URL) {
    return { url: process.env.DATABASE_URL, stop: async () => {} };
  }

  const { default: EmbeddedPostgres } = await import("embedded-postgres");
  const dataDir = mkdtempSync(join(tmpdir(), "vaultkeep-pg-"));
  // Random high port so parallel runs don't collide.
  const port = 54000 + Math.floor(Math.random() * 1000);
  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    port,
    user: "postgres",
    password: "postgres",
    persistent: false,
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("vaultkeep_test");

  return {
    url: `postgresql://postgres:postgres@localhost:${port}/vaultkeep_test`,
    stop: async () => {
      await pg.stop();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Apply the committed migrations (prisma/migrations) to the live database. */
export function migrateDeploy(url: string): void {
  execSync("npx prisma migrate deploy", {
    cwd: SERVER_ROOT,
    env: { ...process.env, DATABASE_URL: url },
    stdio: "pipe",
  });
}
