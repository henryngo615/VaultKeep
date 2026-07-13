import { defineConfig } from "prisma/config";

// Prisma 7 reads the connection URL from here (not from schema.prisma).
// The fallback matches docker-compose.yml so `prisma generate` (which never
// connects) and local migrate work out of the box.
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url:
      process.env.DATABASE_URL ??
      "postgresql://vaultkeep:vaultkeep@localhost:5432/vaultkeep",
  },
});
