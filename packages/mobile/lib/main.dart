import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

import 'core/auth_client.dart';
import 'core/biometric.dart';
import 'core/local_store.dart';
import 'core/sync_client.dart';
import 'core/vault_app.dart';
import 'platform/biometric_platform.dart';
import 'ui/biometric_unlock_screen.dart';
import 'ui/emergency_contacts_screen.dart';
import 'ui/pair_new_device_screen.dart';
import 'ui/recovery_setup_screen.dart';
import 'ui/scan_to_approve_screen.dart';
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
  String? _serverUrl;
  String? _offlineEmail;
  String? _offlineUserId;
  bool _checkingEnrollment = true;
  bool _bioEnrolled = false;
  bool _forcePassword = false;

  // Set while this device is signed in but not yet approved — see
  // PairNewDeviceScreen's doc comment for why a live session can exist here.
  Session? _pendingSession;
  VaultApp? _pendingVault;

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

  Future<void> _onSignedIn(Session session, String serverUrl) =>
      _handleSignedIn(session, serverUrl);

  /// After a recovery-key password reset: the fresh session's key is the
  /// NEW master key, but the local cache and whatever the server holds are
  /// still ciphertext under the OLD one. Unlock with the old key, pull
  /// whatever the server has (also still under the old key), THEN re-encrypt
  /// everything and push it back — see `VaultApp.rekey`.
  Future<void> _onRecoveredSignIn(
          Session session, Uint8List oldMasterKey, String serverUrl) =>
      _handleSignedIn(session, serverUrl, oldMasterKeyForRekey: oldMasterKey);

  Future<void> _handleSignedIn(
    Session session,
    String serverUrl, {
    Uint8List? oldMasterKeyForRekey,
  }) async {
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

    if (oldMasterKeyForRekey != null) {
      await vault.unlockWithKey(oldMasterKeyForRekey);
      try {
        await vault.sync();
      } catch (_) {/* offline-tolerant */}
      await vault.rekey(session.key);
    } else {
      await vault.unlockWithKey(session.key);
    }

    if (await _isDeviceApproved(serverUrl, session.token)) {
      try {
        await vault.sync();
      } catch (_) {/* offline-tolerant */}
      setState(() {
        _session = session;
        _serverUrl = serverUrl;
        _offlineEmail = null;
        _offlineUserId = null;
        _vault = vault;
      });
      return;
    }
    setState(() {
      _pendingSession = session;
      _pendingVault = vault;
      _serverUrl = serverUrl;
    });
  }

  Future<bool> _isDeviceApproved(String serverUrl, String token) async {
    try {
      final res = await http.get(
        Uri.parse('$serverUrl/devices'),
        headers: {'authorization': 'Bearer $token'},
      );
      return res.statusCode == 200;
    } catch (_) {
      return true; // offline: don't block behind a pairing screen either way
    }
  }

  void _finishPendingSignIn() {
    final session = _pendingSession;
    final vault = _pendingVault;
    if (session == null || vault == null) return;
    unawaited(() async {
      try {
        await vault.sync();
      } catch (_) {/* offline-tolerant */}
    }());
    setState(() {
      _session = session;
      _offlineEmail = null;
      _offlineUserId = null;
      _vault = vault;
      _pendingSession = null;
      _pendingVault = null;
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
      _serverUrl = null;
      _offlineEmail = recovered.email;
      _offlineUserId = recovered.userId;
      _vault = vault;
      _pendingSession = null;
      _pendingVault = null;
    });
  }

  void _onLock() {
    _vault?.lock();
    setState(() {
      _vault = null;
      _session = null;
      _serverUrl = null;
      _offlineEmail = null;
      _offlineUserId = null;
      _forcePassword = false;
    });
    _refreshEnrollment();
  }

  @override
  Widget build(BuildContext context) {
    final pendingSession = _pendingSession;
    if (pendingSession != null) {
      return PairNewDeviceScreen(
        baseUrl: _serverUrl!,
        session: pendingSession,
        onApproved: _finishPendingSignIn,
        onSkip: _finishPendingSignIn,
      );
    }
    final vault = _vault;
    if (vault != null && vault.isUnlocked) {
      final session = _session;
      return VaultScreen(
        vault: vault,
        email: session?.email ?? _offlineEmail ?? 'VaultKeep',
        userId: session?.userId ?? _offlineUserId,
        biometric: _biometric,
        onLock: _onLock,
        onScanToApprove: session == null
            ? null
            : () => Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) =>
                      ScanToApproveScreen(baseUrl: _serverUrl!, session: session),
                )),
        onOpenRecoverySetup: session == null
            ? null
            : () => Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) => RecoverySetupScreen(
                      vault: vault, serverUrl: _serverUrl!, token: session.token),
                )),
        onOpenEmergencyContacts: session == null
            ? null
            : () => Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) => EmergencyContactsScreen(
                      vault: vault, serverUrl: _serverUrl!, token: session.token),
                )),
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
    return SignInScreen(onSignedIn: _onSignedIn, onRecovered: _onRecoveredSignIn);
  }
}
