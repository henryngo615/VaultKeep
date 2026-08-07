import 'dart:convert';

import 'package:http/http.dart' as http;

import 'devicekeys.dart' as devicekeys;
import 'pairing.dart';

/// A device record fetched from the server, confirmed pending and identity-
/// verified — safe to show the user for confirmation before signing anything.
class PendingDevice {
  final String id;
  final String name;
  final String platform;
  final String signingPublicKey;
  PendingDevice({
    required this.id,
    required this.name,
    required this.platform,
    required this.signingPublicKey,
  });
}

class PairingException implements Exception {
  final String message;
  PairingException(this.message);
  @override
  String toString() => message;
}

/// Used by an ALREADY-APPROVED device to approve a new one from a scanned QR
/// — the client-side UX on top of the server's existing signature-based
/// approval primitive (`POST /devices/:id/approve`); no server changes.
///
/// Every check — expiry, account match, and the new device's self-signature
/// against its OWN server-recorded public key — happens before this device's
/// approval signature is ever computed or sent, so a malformed, expired, or
/// forged code is rejected locally first.
class PairingClient {
  final String baseUrl;
  final String token; // this (approver) device's own bearer token
  final http.Client _client;
  PairingClient(this.baseUrl, this.token, {http.Client? client})
      : _client = client ?? http.Client();

  /// Validate a scanned code without approving anything yet, so the UI can
  /// show the device's name/platform and ask for explicit confirmation.
  Future<PendingDevice> resolve(String rawQr, {required String myUserId}) async {
    final PairingPayload payload;
    try {
      payload = PairingPayload.decode(rawQr);
    } on FormatException catch (e) {
      throw PairingException(e.message);
    }
    if (payload.isExpired) {
      throw PairingException(
          'This pairing code expired — ask the other device to show a new one.');
    }
    if (payload.userId != myUserId) {
      throw PairingException('This code belongs to a different account.');
    }

    final res = await _client.get(
      Uri.parse('$baseUrl/devices'),
      headers: {'authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) {
      throw PairingException('Could not check your device list — try again.');
    }
    final devices = ((jsonDecode(res.body) as Map<String, dynamic>)['devices']
            as List<dynamic>)
        .cast<Map<String, dynamic>>();
    final matches = devices.where((d) => d['id'] == payload.deviceId);
    if (matches.isEmpty) {
      throw PairingException('No pending device with that code on this account.');
    }
    final record = matches.first;
    if (record['approved'] == true) {
      throw PairingException('That device is already approved.');
    }
    final validSig = await devicekeys.verifyMessage(
      record['signingPublicKey'] as String,
      payload.signedMessage,
      payload.signature,
    );
    if (!validSig) {
      throw PairingException(
          'This pairing code failed to verify — it may be forged or corrupted.');
    }
    return PendingDevice(
      id: record['id'] as String,
      name: record['name'] as String,
      platform: record['platform'] as String,
      signingPublicKey: record['signingPublicKey'] as String,
    );
  }

  /// After the user confirms the device shown by [resolve], sign and send
  /// the actual approval.
  Future<void> approve(
    PendingDevice device, {
    required String myUserId,
    required String myDeviceId,
    required String mySigningPrivateKey,
  }) async {
    final signature = await devicekeys.signMessage(
      mySigningPrivateKey,
      'approve-device:${device.id}',
    );
    final res = await _client.post(
      Uri.parse('$baseUrl/devices/${device.id}/approve'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({
        'userId': myUserId,
        'approverDeviceId': myDeviceId,
        'signature': signature,
      }),
    );
    if (res.statusCode != 200) {
      throw PairingException('The server rejected the approval.');
    }
  }
}
