import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vaultkeep_mobile/core/devicekeys.dart' as devicekeys;
import 'package:vaultkeep_mobile/core/pairing.dart';
import 'package:vaultkeep_mobile/core/pairing_client.dart';

/// A fake server double that implements the REAL approval contract
/// (`device.service.ts`'s `approve()`): the approver must already be
/// `approved`, and its signature over `approve-device:<targetId>` must
/// verify against the approver's OWN stored signing key. This is what makes
/// the "full pairing handshake" tests below prove something real, not just
/// that the client called the right URL.
class FakeDeviceServer {
  final Map<String, Map<String, dynamic>> devices = {}; // id -> record
  final log = <String>[];

  void addDevice({
    required String id,
    required String name,
    required String platform,
    required String signingPublicKey,
    required bool approved,
  }) {
    devices[id] = {
      'id': id,
      'name': name,
      'platform': platform,
      'signingPublicKey': signingPublicKey,
      'approved': approved,
    };
  }

  http.Client client() => MockClient((req) async {
        log.add('${req.method} ${req.url.path}');
        if (req.method == 'GET' && req.url.path == '/devices') {
          return http.Response(
              jsonEncode({'devices': devices.values.toList()}), 200);
        }
        final approveMatch =
            RegExp(r'^/devices/([\w-]+)/approve$').firstMatch(req.url.path);
        if (req.method == 'POST' && approveMatch != null) {
          final targetId = approveMatch.group(1)!;
          final body = jsonDecode(req.body) as Map<String, dynamic>;
          final approver = devices[body['approverDeviceId']];
          final target = devices[targetId];
          if (approver == null || target == null) {
            return http.Response(jsonEncode({'ok': false}), 403);
          }
          if (approver['approved'] != true) {
            return http.Response(jsonEncode({'ok': false}), 403);
          }
          final valid = await devicekeys.verifyMessage(
            approver['signingPublicKey'] as String,
            'approve-device:$targetId',
            body['signature'] as String,
          );
          if (!valid) return http.Response(jsonEncode({'ok': false}), 403);
          target['approved'] = true;
          return http.Response(jsonEncode({'ok': true}), 200);
        }
        return http.Response(jsonEncode({'error': 'not found'}), 404);
      });
}

void main() {
  test(
      'full handshake: a trusted device approves a new one from its QR (two real device identities)',
      () async {
    final trusted = await devicekeys.generateSigningKeys();
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer()
      ..addDevice(
          id: 'desktop-1',
          name: 'Desktop',
          platform: 'darwin',
          signingPublicKey: trusted.publicKey,
          approved: true)
      ..addDevice(
          id: 'phone-1',
          name: 'Mobile',
          platform: 'mobile',
          signingPublicKey: fresh.publicKey,
          approved: false);

    final qr = await createPairingPayload(
      userId: 'user-1',
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
    );

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    final pending = await client.resolve(qr.encode(), myUserId: 'user-1');
    expect(pending.id, 'phone-1');
    expect(pending.name, 'Mobile');

    await client.approve(
      pending,
      myUserId: 'user-1',
      myDeviceId: 'desktop-1',
      mySigningPrivateKey: trusted.privateKey,
    );

    expect(server.devices['phone-1']!['approved'], true);
    expect(server.log, contains('POST /devices/phone-1/approve'));
  });

  test('an expired code is rejected before any server call is made',
      () async {
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer();
    final qr = await createPairingPayload(
      userId: 'user-1',
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
      ttl: const Duration(seconds: -5),
    );

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    await expectLater(
      client.resolve(qr.encode(), myUserId: 'user-1'),
      throwsA(isA<PairingException>()),
    );
    expect(server.log, isEmpty);
  });

  test('a code for a different account is rejected before any server call',
      () async {
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer();
    final qr = await createPairingPayload(
      userId: 'someone-else',
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
    );

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    await expectLater(
      client.resolve(qr.encode(), myUserId: 'user-1'),
      throwsA(isA<PairingException>()),
    );
    expect(server.log, isEmpty);
  });

  test('a tampered code (device id swapped after signing) is rejected without approving',
      () async {
    final trusted = await devicekeys.generateSigningKeys();
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer()
      ..addDevice(
          id: 'desktop-1',
          name: 'Desktop',
          platform: 'darwin',
          signingPublicKey: trusted.publicKey,
          approved: true)
      ..addDevice(
          id: 'phone-1',
          name: 'Mobile',
          platform: 'mobile',
          signingPublicKey: fresh.publicKey,
          approved: false)
      ..addDevice(
          id: 'attacker-device',
          name: 'Attacker',
          platform: 'mobile',
          signingPublicKey: fresh.publicKey,
          approved: false);

    final qr = await createPairingPayload(
      userId: 'user-1',
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
    );
    // Retarget the payload at a different (also-pending) device id without
    // re-signing — the signature was over "pair:phone-1:<exp>".
    final retargeted = qr.encode().replaceFirst('phone-1', 'attacker-device');

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    await expectLater(
      client.resolve(retargeted, myUserId: 'user-1'),
      throwsA(isA<PairingException>()),
    );
    expect(server.devices['attacker-device']!['approved'], false);
    expect(server.log, isNot(contains('POST /devices/attacker-device/approve')));
  });

  test('a device id absent from the account is rejected', () async {
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer()
      ..addDevice(
          id: 'desktop-1',
          name: 'Desktop',
          platform: 'darwin',
          signingPublicKey: (await devicekeys.generateSigningKeys()).publicKey,
          approved: true);
    final qr = await createPairingPayload(
      userId: 'user-1',
      deviceId: 'does-not-exist',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
    );

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    await expectLater(
      client.resolve(qr.encode(), myUserId: 'user-1'),
      throwsA(isA<PairingException>()),
    );
  });

  test('an already-approved device is rejected (nothing left to approve)',
      () async {
    final fresh = await devicekeys.generateSigningKeys();
    final server = FakeDeviceServer()
      ..addDevice(
          id: 'phone-1',
          name: 'Mobile',
          platform: 'mobile',
          signingPublicKey: fresh.publicKey,
          approved: true);
    final qr = await createPairingPayload(
      userId: 'user-1',
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPrivateKeyB64: fresh.privateKey,
    );

    final client =
        PairingClient('http://x', 'trusted-token', client: server.client());
    await expectLater(
      client.resolve(qr.encode(), myUserId: 'user-1'),
      throwsA(isA<PairingException>()),
    );
  });
}
