import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../core/auth_client.dart';
import '../core/pairing_client.dart';

/// Shown on an already-trusted device: scan a pending device's QR code
/// (`PairNewDeviceScreen`), confirm what it says it is, then approve it.
/// Every validation happens in `PairingClient.resolve` before this screen
/// ever lets the user sign an approval.
class ScanToApproveScreen extends StatefulWidget {
  final String baseUrl;
  final Session session;
  const ScanToApproveScreen(
      {super.key, required this.baseUrl, required this.session});

  @override
  State<ScanToApproveScreen> createState() => _ScanToApproveScreenState();
}

class _ScanToApproveScreenState extends State<ScanToApproveScreen> {
  bool _busy = false;
  String _status = "Point the camera at the other device's QR code.";
  PendingDevice? _pending;

  PairingClient get _client =>
      PairingClient(widget.baseUrl, widget.session.token);

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_busy || _pending != null || capture.barcodes.isEmpty) return;
    final raw = capture.barcodes.first.rawValue;
    if (raw == null) return;
    setState(() => _busy = true);
    try {
      final pending = await _client.resolve(raw, myUserId: widget.session.userId);
      setState(() {
        _pending = pending;
        _status = '';
      });
    } on PairingException catch (e) {
      setState(() => _status = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirmApprove() async {
    final pending = _pending;
    if (pending == null) return;
    setState(() => _busy = true);
    try {
      await _client.approve(
        pending,
        myUserId: widget.session.userId,
        myDeviceId: widget.session.device.deviceId,
        mySigningPrivateKey: widget.session.device.signingPrivateKey,
      );
      if (!mounted) return;
      setState(() {
        _status = '${pending.name} approved.';
        _pending = null;
      });
    } on PairingException catch (e) {
      setState(() => _status = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final pending = _pending;
    return Scaffold(
      appBar: AppBar(title: const Text('Approve a device')),
      body: Column(
        children: [
          Expanded(child: MobileScanner(onDetect: _onDetect)),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                Text(_status, key: const Key('scanStatus'), textAlign: TextAlign.center),
                if (pending != null) ...[
                  const SizedBox(height: 8),
                  Text('${pending.name} (${pending.platform})',
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 8),
                  FilledButton(
                    key: const Key('confirmApproveBtn'),
                    onPressed: _busy ? null : _confirmApprove,
                    child: const Text('Approve this device'),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
