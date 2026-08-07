import 'dart:convert';

import 'devicekeys.dart' as devicekeys;

/// What a new (unapproved) device encodes into the QR code an already-
/// trusted device scans to approve it.
///
/// The payload is self-signed by the NEW device's own Ed25519 key (the same
/// key it just registered via `/devices/enroll`), over
/// `pair:<deviceId>:<expiresAtMillis>`. That signature isn't checked by the
/// server — approval there is authenticated purely by the APPROVER's
/// signature (see `pairing_client.dart`) — but it lets the approving device
/// reject a malformed/expired/tampered code locally, before it ever asks the
/// server for the real device record or computes an approval signature.
class PairingPayload {
  static const _version = 1;

  final String userId;
  final String deviceId;
  final String name;
  final DateTime expiresAt;
  final String signature;

  PairingPayload({
    required this.userId,
    required this.deviceId,
    required this.name,
    required this.expiresAt,
    required this.signature,
  });

  /// The exact bytes the new device signs (and the approver re-verifies).
  String get signedMessage => 'pair:$deviceId:${expiresAt.millisecondsSinceEpoch}';

  bool get isExpired => DateTime.now().toUtc().isAfter(expiresAt);

  String encode() => jsonEncode({
        'v': _version,
        'userId': userId,
        'deviceId': deviceId,
        'name': name,
        'exp': expiresAt.millisecondsSinceEpoch,
        'sig': signature,
      });

  /// Throws [FormatException] on anything malformed — missing fields, wrong
  /// version, non-JSON — so callers can fail safe before trusting a scan.
  factory PairingPayload.decode(String raw) {
    final Map<String, dynamic> j;
    try {
      j = jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      throw const FormatException('not a VaultKeep pairing code');
    }
    if (j['v'] != _version) {
      throw const FormatException('unsupported pairing code version');
    }
    final userId = j['userId'];
    final deviceId = j['deviceId'];
    final name = j['name'];
    final exp = j['exp'];
    final sig = j['sig'];
    if (userId is! String ||
        deviceId is! String ||
        name is! String ||
        exp is! int ||
        sig is! String ||
        userId.isEmpty ||
        deviceId.isEmpty ||
        sig.isEmpty) {
      throw const FormatException('malformed pairing code');
    }
    return PairingPayload(
      userId: userId,
      deviceId: deviceId,
      name: name,
      expiresAt: DateTime.fromMillisecondsSinceEpoch(exp, isUtc: true),
      signature: sig,
    );
  }
}

/// Built by the NEW device to show as a QR code. `ttl` bounds how long the
/// code is scannable for — short-lived by design (a stale QR left on screen
/// shouldn't be a standing approval offer).
Future<PairingPayload> createPairingPayload({
  required String userId,
  required String deviceId,
  required String name,
  required String signingPrivateKeyB64,
  Duration ttl = const Duration(minutes: 5),
}) async {
  final expiresAt = DateTime.now().toUtc().add(ttl);
  final unsigned = PairingPayload(
    userId: userId,
    deviceId: deviceId,
    name: name,
    expiresAt: expiresAt,
    signature: '',
  );
  final sig =
      await devicekeys.signMessage(signingPrivateKeyB64, unsigned.signedMessage);
  return PairingPayload(
    userId: userId,
    deviceId: deviceId,
    name: name,
    expiresAt: expiresAt,
    signature: sig,
  );
}
