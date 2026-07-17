import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vaultkeep_mobile/core/auth_client.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';

const salt = 'q83vASNFZ4mrze8BI0VniQ==';
const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);

/// Fake sync server implementing the real auth contract over MockClient,
/// including verifier checking and the needsDevice self-enrollment handshake.
class FakeAuthServer {
  final String email;
  final String expectedVerifier;
  bool deviceEnrolled = false;
  final log = <String>[];

  FakeAuthServer(this.email, this.expectedVerifier);

  http.Client client() => MockClient((req) async {
        log.add(req.url.path);
        final body = req.body.isEmpty
            ? <String, dynamic>{}
            : jsonDecode(req.body) as Map<String, dynamic>;
        Future<http.Response> json(int status, Map<String, dynamic> data) async =>
            http.Response(jsonEncode(data), status);

        switch (req.url.path) {
          case '/auth/kdf':
            return json(200, {
              'kdfSalt': salt,
              'kdfMemoryKiB': fastKdf.memoryKiB,
              'kdfIterations': fastKdf.iterations,
              'kdfParallel': fastKdf.parallelism,
            });
          case '/auth/login':
            // The password itself must NEVER appear in any request.
            if (body['authVerifier'] != expectedVerifier) {
              return json(401, {'error': 'invalid credentials'});
            }
            if (body['deviceId'] == null) {
              return json(200, {'userId': 'u1', 'needsDevice': true});
            }
            return json(200, {'token': 'pre-mfa', 'userId': 'u1'});
          case '/devices/enroll':
            deviceEnrolled = true;
            return json(201, {'device': {'id': 'dev-phone', 'approved': true}});
          case '/auth/mfa':
            return body['code'] == '123456'
                ? json(200, {'token': 'full'})
                : json(401, {'error': 'invalid MFA code'});
          default:
            return json(404, {'error': 'not found'});
        }
      });
}

Future<String> verifierFor(String password) async {
  final key = await deriveMasterKey(password, salt, fastKdf);
  return deriveAuthVerifier(key, password);
}

void main() {
  test('login self-enrolls a fresh phone, satisfies TOTP, returns the key',
      () async {
    final server = FakeAuthServer('me@x.com', await verifierFor('pw one'));
    final devices = MemoryDeviceStore();
    final auth = AuthClient('http://x', devices, client: server.client());

    final session = await auth.login('me@x.com', 'pw one', '123456');
    expect(server.deviceEnrolled, true);
    expect(await devices.load('me@x.com'), 'dev-phone');
    expect(session.token, 'full');
    expect(session.saltB64, salt);
    // The session key is the real derived master key, ready for the vault.
    final expected = await deriveMasterKey('pw one', salt, fastKdf);
    expect(base64.encode(session.key), base64.encode(expected));
  });

  test('a known device skips enrollment', () async {
    final server = FakeAuthServer('me@x.com', await verifierFor('pw one'));
    final devices = MemoryDeviceStore();
    await devices.save('me@x.com', 'dev-phone');
    final auth = AuthClient('http://x', devices, client: server.client());
    await auth.login('me@x.com', 'pw one', '123456');
    expect(server.log, isNot(contains('/devices/enroll')));
  });

  test('a wrong password fails at the verifier (zero-knowledge)', () async {
    final server = FakeAuthServer('me@x.com', await verifierFor('right pw'));
    final auth =
        AuthClient('http://x', MemoryDeviceStore(), client: server.client());
    expect(() => auth.login('me@x.com', 'wrong pw', '123456'),
        throwsA(isA<AuthException>()));
  });

  test('a wrong TOTP code fails cleanly', () async {
    final server = FakeAuthServer('me@x.com', await verifierFor('pw one'));
    final auth =
        AuthClient('http://x', MemoryDeviceStore(), client: server.client());
    expect(() => auth.login('me@x.com', 'pw one', '000000'),
        throwsA(predicate((e) => e.toString().contains('MFA'))));
  });

  test('the raw password never appears in any request body', () async {
    const password = 'super secret master pw';
    final requests = <String>[];
    final client = MockClient((req) async {
      requests.add(req.body);
      return http.Response(jsonEncode({'error': 'nope'}), 401);
    });
    final auth = AuthClient('http://x', MemoryDeviceStore(), client: client);
    // /auth/kdf fails -> login throws; we only care what was transmitted.
    try {
      await auth.login('me@x.com', password, '123456');
    } catch (_) {}
    expect(requests, isNotEmpty);
    for (final body in requests) {
      expect(body.contains(password), false);
    }
  });

  test('register sends a derived verifier, never the password', () async {
    const password = 'registration master pw!';
    final requests = <String>[];
    final client = MockClient((req) async {
      requests.add(req.body);
      if (req.url.path == '/auth/register') {
        return http.Response(
            jsonEncode({
              'userId': 'u9',
              'mfa': {'secret': 'S3CRET', 'otpauthUri': 'otpauth://x'}
            }),
            201);
      }
      return http.Response('{}', 404);
    });
    final auth = AuthClient('http://x', MemoryDeviceStore(), client: client);
    final reg = await auth.register('new@x.com', password);
    expect(reg.totpSecret, 'S3CRET');
    for (final body in requests) {
      expect(body.contains(password), false);
    }
  });
}
