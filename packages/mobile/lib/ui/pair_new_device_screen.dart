import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:qr_flutter/qr_flutter.dart';

import '../core/auth_client.dart';
import '../core/pairing.dart';

/// Shown right after sign-in when this device isn't approved yet: a QR code
/// an already-trusted device can scan (see `ScanToApproveScreen`) instead of
/// retyping the master password on every new device.
///
/// This device already has a full, working session token — auth doesn't
/// gate on device approval, only `/vault/*` and friends do (see CLAUDE.md's
/// security invariants) — so polling `GET /devices` with that token is a
/// reliable, side-effect-free way to detect approval: 200 means trusted, a
/// non-200 (403 "device not approved") means still pending.
class PairNewDeviceScreen extends StatefulWidget {
  final String baseUrl;
  final Session session;
  final VoidCallback onApproved;
  final VoidCallback onSkip;
  final http.Client? httpClient;
  const PairNewDeviceScreen({
    super.key,
    required this.baseUrl,
    required this.session,
    required this.onApproved,
    required this.onSkip,
    this.httpClient,
  });

  @override
  State<PairNewDeviceScreen> createState() => _PairNewDeviceScreenState();
}

class _PairNewDeviceScreenState extends State<PairNewDeviceScreen> {
  static const _ttl = Duration(minutes: 5);
  static const _pollEvery = Duration(seconds: 3);

  late final http.Client _client = widget.httpClient ?? http.Client();
  PairingPayload? _payload;
  Timer? _refreshTimer;
  Timer? _pollTimer;

  @override
  void initState() {
    super.initState();
    _regenerate();
    _pollTimer = Timer.periodic(_pollEvery, (_) => _checkApproved());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _regenerate() async {
    final payload = await createPairingPayload(
      userId: widget.session.userId,
      deviceId: widget.session.device.deviceId,
      name: widget.session.device.name,
      signingPrivateKeyB64: widget.session.device.signingPrivateKey,
      ttl: _ttl,
    );
    if (!mounted) return;
    setState(() => _payload = payload);
    _refreshTimer?.cancel();
    _refreshTimer = Timer(_ttl, _regenerate);
  }

  Future<void> _checkApproved() async {
    try {
      final res = await _client.get(
        Uri.parse('${widget.baseUrl}/devices'),
        headers: {'authorization': 'Bearer ${widget.session.token}'},
      );
      if (res.statusCode == 200) {
        _pollTimer?.cancel();
        widget.onApproved();
      }
    } catch (_) {
      /* offline — keep polling */
    }
  }

  @override
  Widget build(BuildContext context) {
    final payload = _payload;
    return Scaffold(
      appBar: AppBar(title: const Text('Approve this device')),
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'Scan this with a device that already has access to your vault.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                if (payload != null)
                  Container(
                    key: const Key('pairQr'),
                    padding: const EdgeInsets.all(16),
                    color: Colors.white,
                    child: QrImageView(data: payload.encode(), size: 220),
                  )
                else
                  const SizedBox(
                      height: 220, child: Center(child: CircularProgressIndicator())),
                const SizedBox(height: 16),
                const Text('Waiting for approval…',
                    key: Key('pairStatus'),
                    style: TextStyle(color: Color(0xFF8B93A3))),
                const SizedBox(height: 16),
                TextButton(
                  key: const Key('pairSkip'),
                  onPressed: widget.onSkip,
                  child: const Text("I'll approve it later"),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
