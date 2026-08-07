import 'package:flutter/material.dart';

import '../core/recovery_client.dart';
import '../core/vault_app.dart';
import '../core/vault_crypto.dart';

/// Generate (or rotate) a recovery key and register it with the server. The
/// key is shown exactly once — it isn't recoverable from anything the
/// server stores (only a hash of a value derived from it, plus a blob it
/// can't decrypt).
class RecoverySetupScreen extends StatefulWidget {
  final VaultApp vault;
  final String serverUrl;
  final String token;
  final RecoveryClient Function(String baseUrl)? recoveryClientFactory;
  const RecoverySetupScreen({
    super.key,
    required this.vault,
    required this.serverUrl,
    required this.token,
    this.recoveryClientFactory,
  });

  @override
  State<RecoverySetupScreen> createState() => _RecoverySetupScreenState();
}

class _RecoverySetupScreenState extends State<RecoverySetupScreen> {
  String? _recoveryKey;
  String _status = '';
  bool _busy = false;
  bool _saved = false;

  Future<void> _generate() async {
    setState(() {
      _busy = true;
      _status = '';
    });
    final key = widget.vault.snapshotKey();
    try {
      final client =
          (widget.recoveryClientFactory ?? (u) => RecoveryClient(u))(widget.serverUrl);
      final recoveryKey = await client.setup(
        token: widget.token,
        masterKey: key,
        kdfSaltB64: widget.vault.saltB64,
      );
      setState(() => _recoveryKey = recoveryKey);
    } on RecoveryException catch (e) {
      setState(() => _status = e.message);
    } catch (_) {
      setState(() => _status = 'Could not set up recovery — try again.');
    } finally {
      zeroKey(key);
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final recoveryKey = _recoveryKey;
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery key')),
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (recoveryKey == null) ...[
                  const Text(
                    'A recovery key lets you get back into your vault if you '
                    'forget your master password. VaultKeep never sees it — '
                    'store it somewhere safe (a printout, a safe deposit box).',
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    key: const Key('generateRecoveryKeyBtn'),
                    onPressed: _busy ? null : _generate,
                    child: const Text('Generate recovery key'),
                  ),
                ] else ...[
                  const Text('Write this down. It will not be shown again.'),
                  const SizedBox(height: 12),
                  SelectableText(
                    recoveryKey,
                    key: const Key('recoveryKeyText'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 18, color: Color(0xFFC4B5FD)),
                  ),
                  const SizedBox(height: 16),
                  CheckboxListTile(
                    key: const Key('savedCheckbox'),
                    value: _saved,
                    onChanged: (v) => setState(() => _saved = v ?? false),
                    title: const Text("I've saved this somewhere safe"),
                  ),
                  FilledButton(
                    key: const Key('doneBtn'),
                    onPressed: _saved ? () => Navigator.of(context).pop() : null,
                    child: const Text('Done'),
                  ),
                ],
                const SizedBox(height: 12),
                Text(_status,
                    key: const Key('recoverySetupStatus'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: Color(0xFF8B93A3))),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
