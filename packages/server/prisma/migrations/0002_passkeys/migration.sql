-- CreateTable
CREATE TABLE "PasskeyCredential" (
    "credentialId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "publicKeyJwk" TEXT NOT NULL,
    "alg" INTEGER NOT NULL,
    "signCount" INTEGER NOT NULL DEFAULT 0,
    "name" TEXT NOT NULL DEFAULT 'Passkey',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PasskeyCredential_pkey" PRIMARY KEY ("credentialId")
);

-- CreateIndex
CREATE INDEX "PasskeyCredential_userId_idx" ON "PasskeyCredential"("userId");

-- AddForeignKey
ALTER TABLE "PasskeyCredential" ADD CONSTRAINT "PasskeyCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

