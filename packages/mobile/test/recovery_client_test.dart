import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vaultkeep_mobile/core/devicekeys.dart' as devicekeys;
import 'package:vaultkeep_mobile/core/recovery_client.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';

const salt = 'q83vASNFZ4mrze8BI0VniQ==';
const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);

/// A fake server that mirrors the REAL state machine in
/// `packages/server/src/recovery/recovery.service.ts` closely enough to
/// prove the client's request/response handling end-to-end: verifier
/// matching for recovery, and the emergency contact
/// enrolled -> pending -> denied/released lifecycle including the waiting
/// period and signature checks.
class FakeRecoveryServer {
  String? recoveryVerifier;
  String? wrappedKey;
  String loginVerifier = 'irrelevant-to-these-tests';
  final Map<String, Map<String, dynamic>> contacts = {}; // id -> record
  DateTime Function() now = DateTime.now;
  Duration waitFor = const Duration(days: 7);

  http.Client client() => MockClient((req) async {
        Map<String, dynamic> body() =>
            req.body.isEmpty ? {} : jsonDecode(req.body) as Map<String, dynamic>;
        http.Response json(int status, Map<String, dynamic> data) =>
            http.Response(jsonEncode(data), status);

        switch (req.url.path) {
          case '/auth/kdf':
            return json(200, {
              'kdfSalt': salt,
              'kdfMemoryKiB': fastKdf.memoryKiB,
              'kdfIterations': fastKdf.iterations,
              'kdfParallel': fastKdf.parallelism,
            });

          case '/recovery/setup':
            recoveryVerifier = body()['authVerifier'] as String;
            wrappedKey = body()['wrappedKey'] as String;
            return json(201, {'ok': true});

          case '/recovery/status':
            return json(200, {'configured': recoveryVerifier != null});

          case '/recovery/begin':
            if (recoveryVerifier == null || body()['authVerifier'] != recoveryVerifier) {
              return json(401, {'error': 'invalid recovery key'});
            }
            return json(200, {
              'wrappedKey': wrappedKey,
              'kdfSalt': salt,
              'kdfMemoryKiB': fastKdf.memoryKiB,
              'kdfIterations': fastKdf.iterations,
              'kdfParallel': fastKdf.parallelism,
            });

          case '/recovery/complete':
            if (recoveryVerifier == null || body()['authVerifier'] != recoveryVerifier) {
              return json(401, {'error': 'invalid recovery key'});
            }
            loginVerifier = body()['newAuthVerifier'] as String;
            return json(200, {'ok': true});

          case '/emergency/contacts':
            if (req.method == 'POST') {
              final id = 'contact-${contacts.length + 1}';
              contacts[id] = {
                'id': id,
                'contactEmail': body()['contactEmail'],
                'contactSigningPublicKey': body()['contactSigningPublicKey'],
                'ephemeralPublicKey': body()['ephemeralPublicKey'],
                'wrappedKey': body()['wrappedKey'],
                'state': 'enrolled',
                'unlockAt': null,
              };
              return json(201,
                  {'contact': {'id': id, 'contactEmail': body()['contactEmail'], 'state': 'enrolled'}});
            }
            return json(200, {
              'contacts': contacts.values
                  .map((c) => {
                        'id': c['id'],
                        'contactEmail': c['contactEmail'],
                        'state': c['state'],
                        'unlockAt': c['unlockAt'],
                      })
                  .toList()
            });

          case '/emergency/deny':
            final c = contacts[body()['contactId']];
            if (c == null || c['state'] != 'pending') return json(404, {'ok': false});
            c['state'] = 'denied';
            c['unlockAt'] = null;
            return json(200, {'ok': true});

          case '/emergency/request':
            final id = body()['contactId'] as String?;
            final c = contacts[id];
            if (c == null) return json(403, {'error': 'request refused'});
            final valid = await devicekeys.verifyMessage(
                c['contactSigningPublicKey'] as String,
                'emergency-request:$id',
                body()['signature'] as String);
            if (!valid || c['state'] == 'denied' || c['state'] == 'released') {
              return json(403, {'error': 'request refused'});
            }
            if (c['state'] == 'pending') return json(202, {'unlockAt': c['unlockAt']});
            c['state'] = 'pending';
            c['unlockAt'] = now().add(waitFor).toIso8601String();
            return json(202, {'unlockAt': c['unlockAt']});

          case '/emergency/collect':
            final id = body()['contactId'] as String?;
            final c = contacts[id];
            if (c == null) return json(403, {'error': 'collect refused'});
            final valid = await devicekeys.verifyMessage(
                c['contactSigningPublicKey'] as String,
                'emergency-collect:$id',
                body()['signature'] as String);
            if (!valid || c['state'] == 'denied' || c['state'] == 'enrolled') {
              return json(403, {'error': 'collect refused'});
            }
            if (c['state'] == 'pending') {
              if (now().isBefore(DateTime.parse(c['unlockAt'] as String))) {
                return json(403, {'error': 'waiting period active', 'waitUntil': c['unlockAt']});
              }
              c['state'] = 'released';
            }
            return json(200, {
              'ephemeralPublicKey': c['ephemeralPublicKey'],
              'wrappedKey': c['wrappedKey'],
            });

          default:
            return json(404, {'error': 'not found'});
        }
      });
}

void main() {
  group('forgotten-password recovery', () {
    test('round-trip: setup, recover, and reset the password', () async {
      final server = FakeRecoveryServer();
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = await deriveMasterKey('original password', salt, fastKdf);

      final recoveryKey =
          await client.setup(token: 't', masterKey: masterKey, kdfSaltB64: salt);
      expect(recoveryKey, matches(RegExp(r'^VK(-[0-9A-Z]{5}){5}$')));
      expect(await client.isConfigured('t'), true);

      final recovered = await client.recoverMasterKey('me@x.com', recoveryKey);
      expect(recovered.masterKey, masterKey);
      expect(recovered.kdfSaltB64, salt);

      final newMasterKey = await deriveMasterKey('new password', salt, fastKdf);
      await client.completeWithNewPassword(
        email: 'me@x.com',
        recoveryKey: recoveryKey,
        kdfSaltB64: salt,
        newMasterKey: newMasterKey,
        newPassword: 'new password',
      );
      expect(server.loginVerifier,
          await deriveAuthVerifier(newMasterKey, 'new password'));
    });

    test('a wrong recovery key is rejected at every step', () async {
      final server = FakeRecoveryServer();
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = await deriveMasterKey('original password', salt, fastKdf);
      await client.setup(token: 't', masterKey: masterKey, kdfSaltB64: salt);

      await expectLater(
        client.recoverMasterKey('me@x.com', 'VK-WRONG-WRONG-WRONG-WRONG-WRONG'),
        throwsA(isA<RecoveryException>()),
      );
      await expectLater(
        client.completeWithNewPassword(
          email: 'me@x.com',
          recoveryKey: 'VK-WRONG-WRONG-WRONG-WRONG-WRONG',
          kdfSaltB64: salt,
          newMasterKey: Uint8List(32),
          newPassword: 'x',
        ),
        throwsA(isA<RecoveryException>()),
      );
    });

    test('recovering before setup is rejected', () async {
      final server = FakeRecoveryServer();
      final client = RecoveryClient('http://x', client: server.client());
      await expectLater(
        client.recoverMasterKey('nobody@x.com', 'VK-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA'),
        throwsA(isA<RecoveryException>()),
      );
    });
  });

  group('emergency contact', () {
    test('full lifecycle: add, request, wait, collect', () async {
      final server = FakeRecoveryServer()..waitFor = const Duration(seconds: 0);
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i));
      final contactSigning = await devicekeys.generateSigningKeys();
      final contactExchange = await devicekeys.generateExchangeKeys();

      final added = await client.addContact(
        token: 't',
        masterKey: masterKey,
        contactEmail: 'friend@x.com',
        contactSigningPublicKey: contactSigning.publicKey,
        contactExchangePublicKey: contactExchange.publicKey,
      );
      expect(added.state, 'enrolled');
      expect((await client.listContacts('t')).single.id, added.id);

      final unlockAt = await client.requestAccess(added.id, contactSigning.privateKey);
      expect(unlockAt, isNotEmpty);
      expect((await client.listContacts('t')).single.state, 'pending');

      final key = await client.collect(
          added.id, contactSigning.privateKey, contactExchange.privateKey);
      expect(key, masterKey);
      expect((await client.listContacts('t')).single.state, 'released');
    });

    test('collect is refused while the waiting period is active', () async {
      final server = FakeRecoveryServer()..waitFor = const Duration(days: 7);
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i));
      final contactSigning = await devicekeys.generateSigningKeys();
      final contactExchange = await devicekeys.generateExchangeKeys();

      final added = await client.addContact(
        token: 't',
        masterKey: masterKey,
        contactEmail: 'friend@x.com',
        contactSigningPublicKey: contactSigning.publicKey,
        contactExchangePublicKey: contactExchange.publicKey,
      );
      await client.requestAccess(added.id, contactSigning.privateKey);

      await expectLater(
        client.collect(added.id, contactSigning.privateKey, contactExchange.privateKey),
        throwsA(isA<RecoveryException>()),
      );
    });

    test('the owner can deny a pending request, permanently blocking collect',
        () async {
      final server = FakeRecoveryServer()..waitFor = const Duration(seconds: 0);
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i));
      final contactSigning = await devicekeys.generateSigningKeys();
      final contactExchange = await devicekeys.generateExchangeKeys();

      final added = await client.addContact(
        token: 't',
        masterKey: masterKey,
        contactEmail: 'friend@x.com',
        contactSigningPublicKey: contactSigning.publicKey,
        contactExchangePublicKey: contactExchange.publicKey,
      );
      await client.requestAccess(added.id, contactSigning.privateKey);
      expect(await client.denyContact('t', added.id), true);
      expect((await client.listContacts('t')).single.state, 'denied');

      await expectLater(
        client.collect(added.id, contactSigning.privateKey, contactExchange.privateKey),
        throwsA(isA<RecoveryException>()),
      );
    });

    test('a forged request signature is rejected', () async {
      final server = FakeRecoveryServer();
      final client = RecoveryClient('http://x', client: server.client());
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i));
      final contactSigning = await devicekeys.generateSigningKeys();
      final contactExchange = await devicekeys.generateExchangeKeys();
      final impostor = await devicekeys.generateSigningKeys();

      final added = await client.addContact(
        token: 't',
        masterKey: masterKey,
        contactEmail: 'friend@x.com',
        contactSigningPublicKey: contactSigning.publicKey,
        contactExchangePublicKey: contactExchange.publicKey,
      );

      await expectLater(
        client.requestAccess(added.id, impostor.privateKey),
        throwsA(isA<RecoveryException>()),
      );
    });
  });
}
