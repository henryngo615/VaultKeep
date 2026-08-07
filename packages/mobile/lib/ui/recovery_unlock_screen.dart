import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import '../core/auth_client.dart';
import '../core/device_store_file.dart';
import '../core/local_store.dart';
import '../core/recovery_client.dart';
import '../core/vault_crypto.dart';

/// "Forgot your password?" — the client side of the recovery-key flow (#5).
/// Two steps: (1) present the recovery key to reset the account's login
/// credential to a NEW password, unwrapping the OLD master key along the
/// way; (2) sign in normally with that new password — still gated by TOTP,
/// since recovery resets the password, not 2FA — to get a real session and
/// device identity. Re-encrypting the vault from the old key to the new one
/// (`VaultApp.rekey`) is the caller's job once it has that session, since
/// only it knows where the local/synced vault actually lives.
class RecoveryUnlockScreen extends StatefulWidget {
  final String serverUrl;
  final Future<void> Function(Session session, Uint8List oldMasterKey) onRecovered;
  final RecoveryClient Function(String baseUrl)? recoveryClientFactory;
  final AuthClient Function(String baseUrl, DeviceStore devices)? authClientFactory;
  const RecoveryUnlockScreen({
    super.key,
    required this.serverUrl,
    required this.onRecovered,
    this.recoveryClientFactory,
    this.authClientFactory,
  });

  @override
  State<RecoveryUnlockScreen> createState() => _RecoveryUnlockScreenState();
}

class _RecoveryUnlockScreenState extends State<RecoveryUnlockScreen> {
  final _email = TextEditingController();
  final _recoveryKey = TextEditingController();
  final _newPassword = TextEditingController();
  final _confirmPassword = TextEditingController();
  final _code = TextEditingController();
  String _status = '';
  bool _busy = false;
  Uint8List? _oldMasterKey;

  RecoveryClient get _recovery =>
      (widget.recoveryClientFactory ?? (u) => RecoveryClient(u))(widget.serverUrl);

  Future<DeviceStore> _deviceStore() async {
    final dir = await getApplicationSupportDirectory();
    return FileDeviceStore(
        FileStore('${dir.path}${Platform.pathSeparator}devices.json'));
  }

  Future<void> _run(Future<void> Function() body) async {
    setState(() {
      _busy = true;
      _status = '';
    });
    try {
      await body();
    } on RecoveryException catch (e) {
      setState(() => _status = e.message);
    } on AuthException catch (e) {
      setState(() => _status = e.message);
    } catch (_) {
      setState(() => _status = 'Something went wrong — check the details and try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _resetPassword() => _run(() async {
        if (_newPassword.text.isEmpty || _newPassword.text != _confirmPassword.text) {
          setState(() => _status = "Passwords don't match.");
          return;
        }
        final email = _email.text.trim();
        final recoveryKey = _recoveryKey.text.trim();
        final recovered = await _recovery.recoverMasterKey(email, recoveryKey);
        final newMasterKey = await deriveMasterKey(
            _newPassword.text, recovered.kdfSaltB64, recovered.kdf);
        await _recovery.completeWithNewPassword(
          email: email,
          recoveryKey: recoveryKey,
          kdfSaltB64: recovered.kdfSaltB64,
          newMasterKey: newMasterKey,
          newPassword: _newPassword.text,
        );
        setState(() {
          _oldMasterKey = recovered.masterKey;
          _status = 'Password reset. Enter your authenticator code to finish.';
        });
      });

  Future<void> _finishSignIn() => _run(() async {
        final oldKey = _oldMasterKey;
        if (oldKey == null) return;
        final client = (widget.authClientFactory ??
            (u, d) => AuthClient(u, d))(widget.serverUrl, await _deviceStore());
        final session = await client.login(
            _email.text.trim(), _newPassword.text, _code.text.trim());
        await widget.onRecovered(session, oldKey);
      });

  @override
  Widget build(BuildContext context) {
    final resetDone = _oldMasterKey != null;
    return Scaffold(
      appBar: AppBar(title: const Text('Recover your account')),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (!resetDone) ...[
                    Text(
                      'Enter your recovery key to set a new master password. '
                      'Your authenticator app still applies — this resets your '
                      "password, not 2FA.",
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      key: const Key('recoveryEmail'),
                      controller: _email,
                      decoration: const InputDecoration(labelText: 'Email'),
                      keyboardType: TextInputType.emailAddress,
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('recoveryKeyField'),
                      controller: _recoveryKey,
                      decoration: const InputDecoration(
                          labelText: 'Recovery key (VK-XXXXX-...)'),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('newPassword'),
                      controller: _newPassword,
                      obscureText: true,
                      decoration: const InputDecoration(labelText: 'New master password'),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('confirmPassword'),
                      controller: _confirmPassword,
                      obscureText: true,
                      decoration: const InputDecoration(labelText: 'Confirm new password'),
                    ),
                    const SizedBox(height: 16),
                    FilledButton(
                      key: const Key('resetPasswordBtn'),
                      onPressed: _busy ? null : _resetPassword,
                      child: const Text('Reset password'),
                    ),
                  ] else ...[
                    Text('Password reset for ${_email.text.trim()}.',
                        style: Theme.of(context).textTheme.bodyMedium),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('recoveryTotp'),
                      controller: _code,
                      decoration: const InputDecoration(
                          labelText: '6-digit authenticator code'),
                      keyboardType: TextInputType.number,
                    ),
                    const SizedBox(height: 16),
                    FilledButton(
                      key: const Key('finishRecoveryBtn'),
                      onPressed: _busy ? null : _finishSignIn,
                      child: const Text('Sign in'),
                    ),
                  ],
                  const SizedBox(height: 12),
                  Text(_status,
                      key: const Key('recoveryStatus'),
                      textAlign: TextAlign.center,
                      style: const TextStyle(color: Color(0xFF8B93A3))),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
