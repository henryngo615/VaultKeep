import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Per-device key material — a Dart port of `packages/crypto/src/devicekeys.ts`.
/// Each device generates these locally and only ever exports the public
/// halves; the private keys never touch the network. This is what lets a
/// trusted device approve a new one (QR pairing) without the server being
/// able to mint approvals itself.
///
/// The Node server stores public keys as SPKI DER and verifies signatures by
/// importing them the same way (`crypto.createPublicKey({type:"spki", ...})`),
/// so a mobile-generated key must be wire-compatible. Ed25519/X25519 DER
/// wrappers around a raw 32-byte key are FIXED, content-independent prefixes
/// (RFC 8410) — confirmed byte-for-byte against real Node output in
/// `test/fixtures/device_recovery_vectors.json` — so wrapping is just a
/// prefix concat/strip; no general ASN.1 parser is needed.
class DeviceKeyPair {
  final String publicKey; // base64 SPKI DER
  final String privateKey; // base64 PKCS8 DER — stays on device
  DeviceKeyPair(this.publicKey, this.privateKey);
}

const _ed25519SpkiPrefix = [
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, //
];
const _ed25519Pkcs8Prefix = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, //
  0x04, 0x22, 0x04, 0x20, //
];
const _x25519SpkiPrefix = [
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, //
];
const _x25519Pkcs8Prefix = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, //
  0x04, 0x22, 0x04, 0x20, //
];

final _ed25519 = Ed25519();
final _x25519 = X25519();

String _wrapDer(List<int> prefix, List<int> raw) =>
    base64.encode(<int>[...prefix, ...raw]);

/// Strip a fixed-length DER prefix and return the trailing 32 raw key bytes.
Uint8List _unwrapDer(String derB64, int prefixLength) {
  final der = base64.decode(derB64);
  if (der.length != prefixLength + 32) {
    throw const FormatException('malformed DER key (unexpected length)');
  }
  return Uint8List.sublistView(der, prefixLength);
}

/// X25519 keypair for ECDH — sharing the vault key to a new device, or
/// sealing a recovery master key to an emergency contact.
Future<DeviceKeyPair> generateExchangeKeys() async {
  final pair = await _x25519.newKeyPair();
  final priv = await pair.extractPrivateKeyBytes();
  final pub = (await pair.extractPublicKey()).bytes;
  return DeviceKeyPair(
    _wrapDer(_x25519SpkiPrefix, pub),
    _wrapDer(_x25519Pkcs8Prefix, priv),
  );
}

/// Ed25519 keypair for signing device-approval attestations.
Future<DeviceKeyPair> generateSigningKeys() async {
  final pair = await _ed25519.newKeyPair();
  final priv = await pair.extractPrivateKeyBytes();
  final pub = (await pair.extractPublicKey()).bytes;
  return DeviceKeyPair(
    _wrapDer(_ed25519SpkiPrefix, pub),
    _wrapDer(_ed25519Pkcs8Prefix, priv),
  );
}

/// Derive a shared secret between our private key and a peer's public key.
Future<Uint8List> deriveSharedSecret(
  String ourPrivateB64,
  String theirPublicB64,
) async {
  final ourSeed = _unwrapDer(ourPrivateB64, _x25519Pkcs8Prefix.length);
  final theirRaw = _unwrapDer(theirPublicB64, _x25519SpkiPrefix.length);
  final ourPair = await _x25519.newKeyPairFromSeed(ourSeed);
  final secret = await _x25519.sharedSecretKey(
    keyPair: ourPair,
    remotePublicKey: SimplePublicKey(theirRaw, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await secret.extractBytes());
}

Future<String> signMessage(String privateKeyB64, String message) async {
  final seed = _unwrapDer(privateKeyB64, _ed25519Pkcs8Prefix.length);
  final pair = await _ed25519.newKeyPairFromSeed(seed);
  final sig = await _ed25519.sign(utf8.encode(message), keyPair: pair);
  return base64.encode(sig.bytes);
}

Future<bool> verifyMessage(
  String publicKeyB64,
  String message,
  String signatureB64,
) async {
  try {
    final raw = _unwrapDer(publicKeyB64, _ed25519SpkiPrefix.length);
    final sig = Signature(
      base64.decode(signatureB64),
      publicKey: SimplePublicKey(raw, type: KeyPairType.ed25519),
    );
    return await _ed25519.verify(utf8.encode(message), signature: sig);
  } catch (_) {
    return false;
  }
}
