-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "kdfSalt" TEXT NOT NULL,
    "kdfMemoryKiB" INTEGER NOT NULL DEFAULT 262144,
    "kdfIterations" INTEGER NOT NULL DEFAULT 4,
    "kdfParallel" INTEGER NOT NULL DEFAULT 4,
    "authHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "signingPublicKey" TEXT NOT NULL,
    "approved" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VaultItem" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ciphertext" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VaultItem_pkey" PRIMARY KEY ("userId","id")
);

-- CreateTable
CREATE TABLE "MfaMethod" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "label" TEXT NOT NULL DEFAULT '',
    "confirmed" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "MfaMethod_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RecoveryKey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RecoveryKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "deviceId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "VaultItem_userId_updatedAt_idx" ON "VaultItem"("userId", "updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "MfaMethod_userId_kind_key" ON "MfaMethod"("userId", "kind");

-- CreateIndex
CREATE INDEX "AuditLog_userId_createdAt_idx" ON "AuditLog"("userId", "createdAt");

-- AddForeignKey
ALTER TABLE "Device" ADD CONSTRAINT "Device_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VaultItem" ADD CONSTRAINT "VaultItem_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MfaMethod" ADD CONSTRAINT "MfaMethod_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RecoveryKey" ADD CONSTRAINT "RecoveryKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

