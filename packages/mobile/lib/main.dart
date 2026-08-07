import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

import 'core/auth_client.dart';
import 'core/local_store.dart';
import 'core/sync_client.dart';
import 'core/vault_app.dart';
import 'ui/pair_new_device_screen.dart';
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
  VaultApp? _vault;
  Session? _session;
  String? _serverUrl;

  // Set while this device is signed in but not yet approved — see
  // PairNewDeviceScreen's doc comment for why a live session can exist here.
  Session? _pendingSession;
  VaultApp? _pendingVault;

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

    if (await _isDeviceApproved(serverUrl, session.token)) {
      try {
        await vault.sync();
      } catch (_) {/* offline-tolerant */}
      setState(() {
        _session = session;
        _serverUrl = serverUrl;
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
    });
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
    if (vault == null || !vault.isUnlocked) {
      return SignInScreen(onSignedIn: _onSignedIn);
    }
    return VaultScreen(
      vault: vault,
      email: _session!.email,
      onLock: _onLock,
      onScanToApprove: () => Navigator.of(context).push(MaterialPageRoute(
        builder: (_) =>
            ScanToApproveScreen(baseUrl: _serverUrl!, session: _session!),
      )),
    );
  }
}
