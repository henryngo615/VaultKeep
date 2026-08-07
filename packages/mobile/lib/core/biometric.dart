import 'dart:convert';
import 'dart:typed_data';

/// Biometric unlock (Face ID / Touch ID on iOS, fingerprint/face on Android).
///
/// Mirrors the desktop `BiometricUnlock` contract: after a successful
/// password unlock the user may opt in, and we wrap a COPY of the derived
/// MASTER KEY (never the password) behind the platform secure enclave
/// (Keychain / Android Keystore), together with the unlock context (salt +
/// account) it belongs to. A later launch prompts for biometrics; only on
/// success is the key unwrapped and fed to `VaultApp.unlockWithKey()`.
///
/// Storing the wrapped key instead of the password means: no password
/// material at rest in any form, and biometric unlock skips the Argon2id run
/// entirely.
///
/// [SecureEnclave] and [TokenStore] are injected, so this class is fully
/// unit-testable without any platform channel — the real `local_auth` /
/// `flutter_secure_storage` bindings live in `platform/biometric_platform.dart`.
abstract class SecureEnclave {
  /// Is a biometric-gated keystore available on this device right now?
  Future<bool> isAvailable();

  /// Prompt the user for Face ID / fingerprint. Resolves true if they pass.
  Future<bool> promptUser(String reason);

  /// Encrypt with the OS keystore. Returns an opaque string.
  Future<String> encrypt(String plaintext);

  /// Decrypt keystore ciphertext. Throws if the blob is invalid.
  Future<String> decrypt(String ciphertext);
}

abstract class TokenStore {
  Future<String?> read();
  Future<void> write(String token);
  Future<void> clear();
}

/// What biometric unlock needs to reopen the right vault with the right key.
class RecoveredKey {
  final Uint8List key;
  final String saltB64;
  final String? userId;
  final String? email;
  RecoveredKey(this.key, this.saltB64, this.userId, this.email);
}

class BiometricUnlock {
  final SecureEnclave enclave;
  final TokenStore tokens;
  BiometricUnlock(this.enclave, this.tokens);

  /// Whether biometric unlock is offered (hardware present + already enrolled).
  Future<bool> isEnrolled() async =>
      (await enclave.isAvailable()) && (await tokens.read()) != null;

  /// Opt in: wrap a copy of the master key behind the OS keystore.
  Future<void> enroll(
    Uint8List key,
    String saltB64,
    String? userId,
    String? email,
  ) async {
    if (!await enclave.isAvailable()) {
      throw StateError('biometric keystore unavailable on this device');
    }
    final wrapped = jsonEncode({
      'keyB64': base64.encode(key),
      'saltB64': saltB64,
      'userId': userId,
      'email': email,
    });
    await tokens.write(await enclave.encrypt(wrapped));
  }

  /// Opt out / on logout: wipe the wrapped key from the keystore.
  Future<void> unenroll() => tokens.clear();

  /// Prompt for biometrics and, on success, unwrap the master key + its
  /// unlock context so the caller can run `VaultApp.unlockWithKey()`. Returns
  /// null if not enrolled or the biometric prompt was declined/failed. A
  /// wrapped blob that no longer decrypts (keystore reset, tampering) is
  /// wiped — the user falls back to the master password and can re-enroll.
  Future<RecoveredKey?> recoverKey({String reason = 'Unlock VaultKeep'}) async {
    final token = await tokens.read();
    if (token == null || !await enclave.isAvailable()) return null;
    final passed = await enclave.promptUser(reason);
    if (!passed) return null;
    try {
      final wrapped =
          jsonDecode(await enclave.decrypt(token)) as Map<String, dynamic>;
      final key = base64.decode(wrapped['keyB64'] as String);
      if (key.length != 32) {
        throw const FormatException('wrapped key malformed');
      }
      return RecoveredKey(
        Uint8List.fromList(key),
        wrapped['saltB64'] as String,
        wrapped['userId'] as String?,
        wrapped['email'] as String?,
      );
    } catch (_) {
      await tokens.clear(); // stale/corrupt enrollment — password fallback
      return null;
    }
  }
}
