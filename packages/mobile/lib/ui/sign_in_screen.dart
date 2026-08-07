import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import '../core/auth_client.dart';
import '../core/local_store.dart';

/// Sign-in / registration. The master password is fed straight into the core
/// AuthClient (Argon2id on-device) — it never appears in any request.
class SignInScreen extends StatefulWidget {
  final Future<void> Function(Session session, String serverUrl) onSignedIn;
  /// Injectable for widget tests; defaults to the real client factory.
  final AuthClient Function(String baseUrl, DeviceStore devices)? clientFactory;
  const SignInScreen({super.key, required this.onSignedIn, this.clientFactory});

  @override
  State<SignInScreen> createState() => _SignInScreenState();
}

class _SignInScreenState extends State<SignInScreen> {
  // Android emulators reach the host machine at 10.0.2.2.
  final _server = TextEditingController(
      text: Platform.isAndroid ? 'http://10.0.2.2:8787' : 'http://localhost:8787');
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _code = TextEditingController();
  String _status = '';
  bool _busy = false;
  bool _registering = false;
  RegistrationStart? _pendingReg;

  Future<DeviceStore> _deviceStore() async {
    final dir = await getApplicationSupportDirectory();
    return _FileDeviceStore(FileStore('${dir.path}${Platform.pathSeparator}devices.json'));
  }

  AuthClient _client(DeviceStore devices) =>
      (widget.clientFactory ?? (u, d) => AuthClient(u, d))(_server.text.trim(), devices);

  Future<void> _run(Future<void> Function() body) async {
    setState(() => _busy = true);
    try {
      await body();
    } on AuthException catch (e) {
      setState(() => _status = e.message);
    } catch (e) {
      setState(() => _status = 'Could not reach the server');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signIn() => _run(() async {
        setState(() => _status = 'Deriving key on device…');
        final session = await _client(await _deviceStore())
            .login(_email.text.trim(), _password.text, _code.text.trim());
        _password.clear();
        _code.clear();
        setState(() => _status = '');
        await widget.onSignedIn(session, _server.text.trim());
      });

  Future<void> _register() => _run(() async {
        setState(() => _status = 'Creating account…');
        final reg = await _client(await _deviceStore())
            .register(_email.text.trim(), _password.text);
        setState(() {
          _pendingReg = reg;
          _status = '';
        });
      });

  Future<void> _confirmTotp() => _run(() async {
        final ok = await _client(await _deviceStore())
            .confirmTotp(_pendingReg!.userId, _code.text.trim());
        if (!ok) {
          setState(() => _status = "Code didn't match — try the current one.");
          return;
        }
        setState(() {
          _pendingReg = null;
          _registering = false;
          _code.clear();
          _status = '2FA enabled — sign in with your password and a code.';
        });
      });

  @override
  Widget build(BuildContext context) {
    final pending = _pendingReg;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.lock, size: 44, color: Color(0xFF8B5CF6)),
                  const SizedBox(height: 8),
                  Text('VaultKeep',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.headlineMedium),
                  Text(
                    'Zero-knowledge vault — your password never leaves this phone.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 24),
                  if (pending != null) ...[
                    Text('Add this key to your authenticator app:',
                        style: Theme.of(context).textTheme.bodyMedium),
                    const SizedBox(height: 8),
                    SelectableText(pending.totpSecret,
                        key: const Key('totpSecret'),
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                            fontFamily: 'monospace', color: Color(0xFFC4B5FD))),
                    const SizedBox(height: 12),
                    TextField(
                      key: const Key('code'),
                      controller: _code,
                      decoration:
                          const InputDecoration(labelText: '6-digit code'),
                      keyboardType: TextInputType.number,
                    ),
                    const SizedBox(height: 12),
                    FilledButton(
                      key: const Key('confirmBtn'),
                      onPressed: _busy ? null : _confirmTotp,
                      child: const Text('Confirm & finish setup'),
                    ),
                  ] else ...[
                    TextField(
                      key: const Key('email'),
                      controller: _email,
                      decoration: const InputDecoration(labelText: 'Email'),
                      keyboardType: TextInputType.emailAddress,
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('password'),
                      controller: _password,
                      obscureText: true,
                      decoration:
                          const InputDecoration(labelText: 'Master password'),
                    ),
                    if (!_registering) ...[
                      const SizedBox(height: 8),
                      TextField(
                        key: const Key('code'),
                        controller: _code,
                        decoration: const InputDecoration(
                            labelText: '6-digit authenticator code'),
                        keyboardType: TextInputType.number,
                      ),
                    ],
                    const SizedBox(height: 16),
                    FilledButton(
                      key: const Key('primaryBtn'),
                      onPressed:
                          _busy ? null : (_registering ? _register : _signIn),
                      child: Text(_registering ? 'Create account' : 'Unlock'),
                    ),
                    TextButton(
                      key: const Key('modeToggle'),
                      onPressed: _busy
                          ? null
                          : () => setState(() {
                                _registering = !_registering;
                                _status = '';
                              }),
                      child: Text(_registering
                          ? 'Have an account? Sign in'
                          : 'New here? Create an account'),
                    ),
                    ExpansionTile(
                      title: Text('Server',
                          style: Theme.of(context).textTheme.bodySmall),
                      tilePadding: EdgeInsets.zero,
                      children: [
                        TextField(
                          key: const Key('server'),
                          controller: _server,
                          decoration:
                              const InputDecoration(labelText: 'Server URL'),
                        ),
                      ],
                    ),
                  ],
                  const SizedBox(height: 12),
                  Text(_status,
                      key: const Key('status'),
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

/// Device identities persisted as a tiny JSON file. Not secret-free like the
/// old deviceId-only version — this now includes each account's signing/
/// exchange PRIVATE keys, so unlike the vault blob this file deliberately
/// lives unencrypted (there's no master key available before sign-in to
/// protect it with), same tradeoff desktop's on-disk `device.json` makes.
class _FileDeviceStore implements DeviceStore {
  final LocalStore store;
  _FileDeviceStore(this.store);

  Future<Map<String, dynamic>> _read() async {
    final raw = await store.readRaw();
    if (raw == null) return {};
    try {
      return Map<String, dynamic>.from(jsonDecode(raw) as Map);
    } catch (_) {
      return {};
    }
  }

  @override
  Future<DeviceIdentity?> load(String email) async {
    final j = (await _read())[email.toLowerCase()];
    if (j == null) return null;
    return DeviceIdentity.fromJson(Map<String, dynamic>.from(j as Map));
  }

  @override
  Future<void> save(String email, DeviceIdentity identity) async {
    final m = await _read();
    m[email.toLowerCase()] = identity.toJson();
    await store.writeRaw(jsonEncode(m));
  }
}
