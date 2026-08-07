import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../core/biometric.dart';

/// Real device binding for [SecureEnclave]: `local_auth` gates access with a
/// biometric prompt, and `flutter_secure_storage` — backed by the iOS
/// Keychain / Android Keystore — is the OS keystore that actually holds the
/// wrapped key at rest. This class does no encryption of its own; storing a
/// value in secure storage under a fixed slot IS the "encrypt" step, keyed to
/// this device the same way Electron's `safeStorage` is on desktop.
class PlatformSecureEnclave implements SecureEnclave {
  final LocalAuthentication _auth;
  final FlutterSecureStorage _storage;
  static const _slot = 'vaultkeep_biometric_blob';

  PlatformSecureEnclave({LocalAuthentication? auth, FlutterSecureStorage? storage})
      : _auth = auth ?? LocalAuthentication(),
        _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<bool> isAvailable() async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final supported = await _auth.isDeviceSupported();
      return canCheck && supported;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<bool> promptUser(String reason) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(biometricOnly: true, stickyAuth: true),
      );
    } catch (_) {
      return false;
    }
  }

  @override
  Future<String> encrypt(String plaintext) async {
    await _storage.write(key: _slot, value: plaintext);
    return _slot;
  }

  @override
  Future<String> decrypt(String ciphertext) async {
    final value = await _storage.read(key: ciphertext);
    if (value == null) throw StateError('no value at secure storage slot');
    return value;
  }
}

/// [TokenStore] for [BiometricUnlock]. The value it carries is just the
/// secure-storage slot name from [PlatformSecureEnclave.encrypt] — the actual
/// secret lives in that slot, not here — so `clear()` must wipe both.
class SecureStorageTokenStore implements TokenStore {
  final FlutterSecureStorage _storage;
  static const _flag = 'vaultkeep_biometric_enrolled';

  SecureStorageTokenStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<String?> read() => _storage.read(key: _flag);

  @override
  Future<void> write(String token) => _storage.write(key: _flag, value: token);

  @override
  Future<void> clear() async {
    await _storage.delete(key: _flag);
    await _storage.delete(key: PlatformSecureEnclave._slot);
  }
}
