-- Recovery: wrapped master key behind a client-held recovery key, plus
-- emergency contacts with a server-enforced waiting period. Every secret
-- column is ciphertext or a hash — the server can time releases, not decrypt.

-- The old RecoveryKey table (keyHash placeholder) was never written to by any
-- released code path; replace it with the real shape, one row per user.
DROP TABLE IF EXISTS "RecoveryKey";

CREATE TABLE "RecoveryKey" (
    "userId" TEXT NOT NULL,
    "verifierHash" TEXT NOT NULL,
    "wrappedKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RecoveryKey_pkey" PRIMARY KEY ("userId"),
    CONSTRAINT "RecoveryKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "EmergencyContact" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "contactEmail" TEXT NOT NULL,
    "contactSigningPublicKey" TEXT NOT NULL,
    "ephemeralPublicKey" TEXT NOT NULL,
    "wrappedKey" TEXT NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'enrolled',
    "unlockAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmergencyContact_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "EmergencyContact_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "EmergencyContact_userId_idx" ON "EmergencyContact"("userId");
