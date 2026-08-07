import 'package:flutter/material.dart';

import '../core/biometric.dart';

/// Shown on launch when a wrapped key is already enrolled: one biometric
/// prompt reopens the vault with no password and no Argon2id wait. Falls
/// back to the normal sign-in screen on decline/failure, or if the user asks.
class BiometricUnlockScreen extends StatefulWidget {
  final BiometricUnlock biometric;
  final Future<void> Function(RecoveredKey recovered) onUnlocked;
  final VoidCallback onUsePassword;
  const BiometricUnlockScreen({
    super.key,
    required this.biometric,
    required this.onUnlocked,
    required this.onUsePassword,
  });

  @override
  State<BiometricUnlockScreen> createState() => _BiometricUnlockScreenState();
}

class _BiometricUnlockScreenState extends State<BiometricUnlockScreen> {
  bool _busy = false;
  String _status = '';

  @override
  void initState() {
    super.initState();
    _tryUnlock();
  }

  Future<void> _tryUnlock() async {
    setState(() {
      _busy = true;
      _status = '';
    });
    final recovered = await widget.biometric.recoverKey();
    if (!mounted) return;
    if (recovered == null) {
      setState(() {
        _busy = false;
        _status = 'Biometric unlock unavailable or declined.';
      });
      return;
    }
    await widget.onUnlocked(recovered);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.fingerprint, size: 64, color: Color(0xFF8B5CF6)),
                const SizedBox(height: 16),
                Text('VaultKeep', style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 16),
                Text(_status,
                    key: const Key('bioStatus'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: Color(0xFF8B93A3))),
                const SizedBox(height: 16),
                FilledButton(
                  key: const Key('bioRetry'),
                  onPressed: _busy ? null : _tryUnlock,
                  child: const Text('Unlock with biometrics'),
                ),
                TextButton(
                  key: const Key('bioUsePassword'),
                  onPressed: _busy ? null : widget.onUsePassword,
                  child: const Text('Use master password instead'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
