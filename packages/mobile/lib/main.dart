import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'core/auth_client.dart';
import 'core/biometric.dart';
import 'core/local_store.dart';
import 'core/sync_client.dart';
import 'core/vault_app.dart';
import 'platform/biometric_platform.dart';
import 'ui/biometric_unlock_screen.dart';
import 'ui/sign_in_screen.dart';
import 'ui/vault_screen.dart';

void main() => runApp(const VaultKeepApp());

/// App-level wiring: real file-backed stores under the app-support directory.
/// All crypto happens in core/ — screens never see the key.
class VaultKeepApp extends StatelessWidget {
  const VaultKeepApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VaultKeep',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF6366F1),
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: const Color(0xFF0F1115),
        useMaterial3: true,
      ),
      home: const _Root(),
    );
  }
}

class _Root extends StatefulWidget {
  const _Root();
  @override
  State<_Root> createState() => _RootState();
}

class _RootState extends State<_Root> {
  final _biometric =
      BiometricUnlock(PlatformSecureEnclave(), SecureStorageTokenStore());

  VaultApp? _vault;
  Session? _session;
  String? _offlineEmail;
  String? _offlineUserId;
  bool _checkingEnrollment = true;
  bool _bioEnrolled = false;
  bool _forcePassword = false;

  @override
  void initState() {
    super.initState();
    _refreshEnrollment();
  }

  Future<void> _refreshEnrollment() async {
    final enrolled = await _biometric.isEnrolled();
    if (mounted) {
      setState(() {
        _bioEnrolled = enrolled;
        _checkingEnrollment = false;
      });
    }
  }

  Future<void> _onSignedIn(Session session, String serverUrl) async {
    final dir = await getApplicationSupportDirectory();
    // Per-account vault file so switching accounts never mixes ciphertext.
    final store =
        FileStore('${dir.path}${Platform.pathSeparator}${session.userId}.enc');
    final vault = VaultApp(
      session.saltB64,
      store,
      HttpTransport(serverUrl, session.token),
      kdf: session.kdf,
    );
    await vault.unlockWithKey(session.key);
    try {
      await vault.sync();
    } catch (_) {/* offline-tolerant */}
    setState(() {
      _session = session;
      _offlineEmail = null;
      _offlineUserId = null;
      _vault = vault;
    });
  }

  /// Biometric unlock never touches the network — same as desktop's "offline
  /// unlock of the enrolled vault": no transport, so `sync()` is skipped
  /// until the next full password sign-in re-establishes a token.
  Future<void> _onBiometricUnlocked(RecoveredKey recovered) async {
    final dir = await getApplicationSupportDirectory();
    final fileName = recovered.userId != null ? '${recovered.userId}.enc' : 'vault.enc';
    final store = FileStore('${dir.path}${Platform.pathSeparator}$fileName');
    final vault = VaultApp(recovered.saltB64, store, null);
    await vault.unlockWithKey(recovered.key);
    setState(() {
      _session = null;
      _offlineEmail = recovered.email;
      _offlineUserId = recovered.userId;
      _vault = vault;
    });
  }

  void _onLock() {
    _vault?.lock();
    setState(() {
      _vault = null;
      _session = null;
      _offlineEmail = null;
      _offlineUserId = null;
      _forcePassword = false;
    });
    _refreshEnrollment();
  }

  @override
  Widget build(BuildContext context) {
    final vault = _vault;
    if (vault != null && vault.isUnlocked) {
      return VaultScreen(
        vault: vault,
        email: _session?.email ?? _offlineEmail ?? 'VaultKeep',
        userId: _session?.userId ?? _offlineUserId,
        biometric: _biometric,
        onLock: _onLock,
      );
    }
    if (_checkingEnrollment) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_bioEnrolled && !_forcePassword) {
      return BiometricUnlockScreen(
        biometric: _biometric,
        onUnlocked: _onBiometricUnlocked,
        onUsePassword: () => setState(() => _forcePassword = true),
      );
    }
    return SignInScreen(onSignedIn: _onSignedIn);
  }
}
