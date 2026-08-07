import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vaultkeep_mobile/core/biometric.dart';
import 'package:vaultkeep_mobile/core/local_store.dart';
import 'package:vaultkeep_mobile/core/vault_app.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';

const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);
const salt = 'q83vASNFZ4mrze8BI0VniQ==';

/// Fully mockable biometric layer — no platform channel anywhere. The mock
/// enclave is a real AES-GCM keystore with a device-local key (reusing the
/// tested `vault_crypto` blob format), plus scriptable availability and
/// prompt outcomes, so every acceptance path is exercised: enroll →
/// biometric unlock, declined prompt, unavailable hardware, disable-wipes-
/// key, stale/tampered wrapped blobs.
class MockEnclave implements SecureEnclave {
  bool available = true;
  bool promptResult = true;
  int promptCount = 0;
  final Uint8List _deviceKey = Uint8List.fromList(
      List.generate(32, (_) => Random.secure().nextInt(256)));

  @override
  Future<bool> isAvailable() async => available;

  @override
  Future<bool> promptUser(String reason) async {
    promptCount++;
    return promptResult;
  }

  @override
  Future<String> encrypt(String plaintext) => encryptBlob(_deviceKey, plaintext);

  @override
  Future<String> decrypt(String ciphertext) => decryptBlob(_deviceKey, ciphertext);
}

class MemoryTokenStore implements TokenStore {
  String? token;

  @override
  Future<String?> read() async => token;

  @override
  Future<void> write(String t) async => token = t;

  @override
  Future<void> clear() async => token = null;
}

class _Fixture {
  final MockEnclave enclave;
  final MemoryTokenStore tokens;
  final BiometricUnlock bio;
  _Fixture(this.enclave, this.tokens, this.bio);
}

_Fixture _setup() {
  final enclave = MockEnclave();
  final tokens = MemoryTokenStore();
  return _Fixture(enclave, tokens, BiometricUnlock(enclave, tokens));
}

/// Password-unlock a vault with one item, then enroll its key.
Future<MemoryStore> _enrolledVault(BiometricUnlock bio) async {
  final store = MemoryStore();
  final app = VaultApp(salt, store, null, kdf: fastKdf);
  await app.unlock('master password 1');
  await app.add(title: 'GitHub', username: 'h', password: 'p', url: '');
  final key = app.snapshotKey();
  await bio.enroll(key, salt, null, null);
  zeroKey(key); // caller wipes its copy after wrapping
  app.lock();
  return store;
}

void main() {
  group('BiometricUnlock (wrapped master key behind the OS keystore)', () {
    test(
        'after one password unlock + enroll, a biometric prompt unlocks the vault',
        () async {
      final f = _setup();
      final store = await _enrolledVault(f.bio);

      final recovered = await f.bio.recoverKey();
      expect(f.enclave.promptCount, 1);
      expect(recovered, isNotNull);
      expect(recovered!.saltB64, salt);
      expect(recovered.userId, isNull);

      // No password, no KDF — the unwrapped key opens the same vault.
      final app = VaultApp(recovered.saltB64, store, null, kdf: fastKdf);
      await app.unlockWithKey(recovered.key);
      expect(app.list().map((i) => i.title).toList(), ['GitHub']);
    });

    test('a declined biometric prompt yields no key', () async {
      final f = _setup();
      await _enrolledVault(f.bio);
      f.enclave.promptResult = false;
      expect(await f.bio.recoverKey(), isNull);
    });

    test('enroll is refused when no biometric keystore is available',
        () async {
      final f = _setup();
      f.enclave.available = false;
      await expectLater(
        f.bio.enroll(Uint8List(32), salt, null, null),
        throwsA(isA<StateError>()),
      );
      expect(await f.bio.isEnrolled(), false);
    });

    test('hardware disappearing after enrollment falls back to the password',
        () async {
      final f = _setup();
      await _enrolledVault(f.bio);
      f.enclave.available = false;
      expect(await f.bio.isEnrolled(), false);
      expect(await f.bio.recoverKey(), isNull);
      expect(await f.tokens.read(), isNotNull); // untouched — comes back with the hardware
    });

    test('disabling biometrics wipes the wrapped key from the keystore',
        () async {
      final f = _setup();
      await _enrolledVault(f.bio);
      expect(await f.tokens.read(), isNotNull);
      await f.bio.unenroll();
      expect(await f.tokens.read(), isNull);
      expect(await f.bio.isEnrolled(), false);
      expect(await f.bio.recoverKey(), isNull);
    });

    test('a tampered wrapped blob is rejected AND wiped (password fallback)',
        () async {
      final f = _setup();
      await _enrolledVault(f.bio);
      final blob = base64.decode((await f.tokens.read())!);
      blob[15] ^= 0xff;
      await f.tokens.write(base64.encode(blob));

      expect(await f.bio.recoverKey(), isNull);
      expect(await f.tokens.read(), isNull); // stale enrollment cleaned up
    });

    test('a stale wrapped key cannot open a re-keyed vault (GCM gate)',
        () async {
      final f = _setup();
      final store = await _enrolledVault(f.bio);

      // The user changes their master password -> vault re-encrypted.
      final app = VaultApp(salt, store, null, kdf: fastKdf);
      await app.unlock('master password 1');
      final items = app.list();
      final rekeyed = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
      await rekeyed.unlock('NEW master password');
      for (final it in items) {
        await rekeyed.add(
          title: it.title,
          username: it.username,
          password: it.password,
          url: it.url,
        );
      }
      await store.writeRaw((await rekeyed.store.readRaw())!);

      final recovered = await f.bio.recoverKey();
      final reopened = VaultApp(salt, store, null, kdf: fastKdf);
      await expectLater(
          reopened.unlockWithKey(recovered!.key), throwsA(anything));
    });

    test('enrollment stores the account context for per-account vaults',
        () async {
      final f = _setup();
      await f.bio.enroll(Uint8List(32), 'c2FsdA==', 'user-42', 'me@x.com');
      final recovered = await f.bio.recoverKey();
      expect(recovered!.userId, 'user-42');
      expect(recovered.saltB64, 'c2FsdA==');
      expect(recovered.email, 'me@x.com');
    });

    test('locking the app zeroes the key VaultApp took ownership of',
        () async {
      final f = _setup();
      final store = await _enrolledVault(f.bio);
      final recovered = await f.bio.recoverKey();
      final app = VaultApp(salt, store, null, kdf: fastKdf);
      await app.unlockWithKey(recovered!.key);
      app.lock();
      expect(recovered.key.every((b) => b == 0), true);
      expect(() => app.list(), throwsStateError);
    });
  });
}
