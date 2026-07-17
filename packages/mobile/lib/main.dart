import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'core/auth_client.dart';
import 'core/local_store.dart';
import 'core/sync_client.dart';
import 'core/vault_app.dart';
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
      _vault = vault;
    });
  }

  void _onLock() {
    _vault?.lock();
    setState(() {
      _vault = null;
      _session = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final vault = _vault;
    if (vault == null || !vault.isUnlocked) {
      return SignInScreen(onSignedIn: _onSignedIn);
    }
    return VaultScreen(
      vault: vault,
      email: _session!.email,
      onLock: _onLock,
    );
  }
}
