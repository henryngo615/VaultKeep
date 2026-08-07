import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'devicekeys.dart' as devicekeys;
import 'vault_crypto.dart';

/// Recovery kit — a Dart port of `packages/crypto/src/recovery.ts`. The
/// escape hatch for a forgotten master password that keeps the server blind.
///
/// At setup the CLIENT generates a high-entropy recovery key and splits it,
/// via HKDF with independent info labels, into:
///
///   authVerifier — sent to the server, which stores only an Argon2 hash of it
///   wrapKey      — NEVER leaves the client; AES-256-GCM-wraps the master key
///
/// The server stores the wrapped blob. Holding blob + verifier hash, it
/// still cannot derive wrapKey (HKDF is one-way and the two outputs are
/// independent), so it can never decrypt. Recovery = present the verifier,
/// get the blob back, unwrap locally.
///
/// Emergency access wraps the master key TO A CONTACT's X25519 public key
/// (ephemeral-key ECDH, like an age/NaCl "seal"): only the contact's private
/// key — which the server never sees — can unwrap what the server releases
/// after the waiting period.
const _groups = 5;
const _groupLen = 5;
// Crockford base32: no I/L/O/U — unambiguous to read off paper.
const _alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/// e.g. VK-1A2B3-C4D5E-F6G7H-J8K9M-NP0QR (25 chars ~125 bits of entropy).
String generateRecoveryKey() {
  final rng = Random.secure();
  final groups = <String>[];
  for (var g = 0; g < _groups; g++) {
    final buf = StringBuffer();
    for (var i = 0; i < _groupLen; i++) {
      // Rejection sampling for an unbiased draw from the 32-char alphabet.
      int b;
      do {
        b = rng.nextInt(256);
      } while (b >= 224); // 224 = 7 * 32
      buf.write(_alphabet[b % 32]);
    }
    groups.add(buf.toString());
  }
  return 'VK-${groups.join('-')}';
}

/// Forgiving normalization: case, separators, and the easy misreadings.
String normalizeRecoveryKey(String input) {
  var s = input.toUpperCase().replaceAll(RegExp(r'[^0-9A-Z]'), '');
  if (s.startsWith('VK')) s = s.substring(2);
  return s.replaceAll(RegExp(r'[IL]'), '1').replaceAll('O', '0');
}

class RecoveryParts {
  /// Present to the server; it stores/checks a hash, nothing more.
  final String authVerifier;

  /// Client-only: unwraps the master key.
  final Uint8List wrapKey;
  RecoveryParts(this.authVerifier, this.wrapKey);
}

/// Split the recovery key into its two independent halves.
Future<RecoveryParts> deriveRecoveryParts(
    String recoveryKey, String saltB64) async {
  final ikm = utf8.encode(normalizeRecoveryKey(recoveryKey));
  final salt = base64.decode(saltB64);
  final auth = await _hkdfSha256(
    ikm: ikm,
    salt: salt,
    info: utf8.encode('vaultkeep-recovery-auth'),
    length: 32,
  );
  final wrap = await _hkdfSha256(
    ikm: ikm,
    salt: salt,
    info: utf8.encode('vaultkeep-recovery-wrap'),
    length: 32,
  );
  return RecoveryParts(base64.encode(auth), wrap);
}

/// AES-256-GCM-wrap the master key for server-side storage of the blob.
Future<String> wrapMasterKey(Uint8List wrapKey, Uint8List masterKey) =>
    encryptBlob(wrapKey, base64.encode(masterKey));

/// Unwrap; throws (GCM auth tag) on a wrong recovery key or tampered blob.
Future<Uint8List> unwrapMasterKey(Uint8List wrapKey, String blobB64) async =>
    Uint8List.fromList(base64.decode(await decryptBlob(wrapKey, blobB64)));

class ContactWrappedKey {
  /// Ephemeral X25519 public key used for this seal (not secret).
  final String ephemeralPublicKey;

  /// The master key, decryptable only with the contact's private key.
  final String blob;
  ContactWrappedKey(this.ephemeralPublicKey, this.blob);

  Map<String, dynamic> toJson() =>
      {'ephemeralPublicKey': ephemeralPublicKey, 'blob': blob};
  factory ContactWrappedKey.fromJson(Map<String, dynamic> j) =>
      ContactWrappedKey(
          j['ephemeralPublicKey'] as String, j['blob'] as String);
}

/// Seal the master key to an emergency contact's X25519 public key.
Future<ContactWrappedKey> wrapKeyForContact(
    Uint8List masterKey, String contactPublicKeyB64) async {
  final ephemeral = await devicekeys.generateExchangeKeys();
  final wrapKey = await _contactWrapKey(ephemeral.privateKey, contactPublicKeyB64);
  final blob = await encryptBlob(wrapKey, base64.encode(masterKey));
  return ContactWrappedKey(ephemeral.publicKey, blob);
}

/// Contact side: unseal with their private key + the stored ephemeral public.
Future<Uint8List> unwrapKeyFromContact(
    String contactPrivateKeyB64, ContactWrappedKey wrapped) async {
  final wrapKey =
      await _contactWrapKey(contactPrivateKeyB64, wrapped.ephemeralPublicKey);
  return Uint8List.fromList(
      base64.decode(await decryptBlob(wrapKey, wrapped.blob)));
}

Future<Uint8List> _contactWrapKey(
    String privateKeyB64, String publicKeyB64) async {
  final shared = await devicekeys.deriveSharedSecret(privateKeyB64, publicKeyB64);
  return _hkdfSha256(
    ikm: shared,
    salt: const [],
    info: utf8.encode('vaultkeep-emergency-wrap'),
    length: 32,
  );
}

/// RFC 5869 HKDF-SHA256 — matches Node's
/// `crypto.hkdfSync("sha256", ikm, salt, info, length)` byte-for-byte
/// (proven against fixtures generated by the node core in
/// test/fixtures/device_recovery_vectors.json). Built on `Hmac.sha256()`,
/// the same already-proven primitive `vault_crypto.dart` uses for the login
/// auth verifier, rather than a less-exercised HKDF API.
Future<Uint8List> _hkdfSha256({
  required List<int> ikm,
  required List<int> salt,
  required List<int> info,
  required int length,
}) async {
  final hmac = Hmac.sha256();
  // RFC 5869: an empty salt is treated as HashLen zero bytes.
  final effectiveSalt = salt.isEmpty ? List<int>.filled(32, 0) : salt;
  final prk =
      (await hmac.calculateMac(ikm, secretKey: SecretKey(effectiveSalt))).bytes;

  final okm = <int>[];
  var previous = <int>[];
  var counter = 1;
  while (okm.length < length) {
    final input = [...previous, ...info, counter];
    previous = (await hmac.calculateMac(input, secretKey: SecretKey(prk))).bytes;
    okm.addAll(previous);
    counter++;
  }
  return Uint8List.fromList(okm.sublist(0, length));
}
