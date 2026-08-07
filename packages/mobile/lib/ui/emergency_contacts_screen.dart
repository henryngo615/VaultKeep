import 'package:flutter/material.dart';

import '../core/recovery_client.dart';
import '../core/vault_app.dart';
import '../core/vault_crypto.dart';

/// Owner-side emergency-contact management: add a contact (their public keys
/// are shared out-of-band — this app doesn't broker that exchange), see
/// pending requests, and deny one within its waiting period. The contact's
/// own "request access" / "collect" actions are a separate, pre-auth flow
/// (`RecoveryClient.requestAccess`/`.collect`) on THEIR device, not covered
/// by this screen.
class EmergencyContactsScreen extends StatefulWidget {
  final VaultApp vault;
  final String serverUrl;
  final String token;
  final RecoveryClient Function(String baseUrl)? recoveryClientFactory;
  const EmergencyContactsScreen({
    super.key,
    required this.vault,
    required this.serverUrl,
    required this.token,
    this.recoveryClientFactory,
  });

  @override
  State<EmergencyContactsScreen> createState() => _EmergencyContactsScreenState();
}

class _EmergencyContactsScreenState extends State<EmergencyContactsScreen> {
  late final RecoveryClient _client =
      (widget.recoveryClientFactory ?? (u) => RecoveryClient(u))(widget.serverUrl);

  List<EmergencyContact> _contacts = [];
  String _status = '';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final contacts = await _client.listContacts(widget.token);
    if (mounted) setState(() => _contacts = contacts);
  }

  Future<void> _addContact() async {
    final email = TextEditingController();
    final signingKey = TextEditingController();
    final exchangeKey = TextEditingController();
    final ok = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(
          left: 16,
          right: 16,
          top: 16,
          bottom: MediaQuery.of(ctx).viewInsets.bottom + 16,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Add emergency contact', style: Theme.of(ctx).textTheme.titleLarge),
            const SizedBox(height: 8),
            const Text(
              "Ask your contact to share their VaultKeep public keys with you "
              "first (from their own device) — VaultKeep never brokers this.",
              style: TextStyle(fontSize: 12),
            ),
            const SizedBox(height: 12),
            TextField(
                key: const Key('contactEmail'),
                controller: email,
                decoration: const InputDecoration(labelText: "Contact's email")),
            const SizedBox(height: 8),
            TextField(
                key: const Key('contactSigningKey'),
                controller: signingKey,
                decoration:
                    const InputDecoration(labelText: "Contact's signing public key")),
            const SizedBox(height: 8),
            TextField(
                key: const Key('contactExchangeKey'),
                controller: exchangeKey,
                decoration:
                    const InputDecoration(labelText: "Contact's exchange public key")),
            const SizedBox(height: 16),
            FilledButton(
              key: const Key('saveContactBtn'),
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Add contact'),
            ),
          ],
        ),
      ),
    );
    if (ok != true || email.text.trim().isEmpty) return;

    setState(() => _busy = true);
    final key = widget.vault.snapshotKey();
    try {
      await _client.addContact(
        token: widget.token,
        masterKey: key,
        contactEmail: email.text.trim(),
        contactSigningPublicKey: signingKey.text.trim(),
        contactExchangePublicKey: exchangeKey.text.trim(),
      );
      await _refresh();
    } on RecoveryException catch (e) {
      setState(() => _status = e.message);
    } finally {
      zeroKey(key);
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _deny(EmergencyContact c) async {
    setState(() => _busy = true);
    try {
      await _client.denyContact(widget.token, c.id);
      await _refresh();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Emergency contacts'),
        actions: [
          IconButton(
              key: const Key('addContactBtn'),
              tooltip: 'Add contact',
              onPressed: _busy ? null : _addContact,
              icon: const Icon(Icons.person_add)),
        ],
      ),
      body: Column(
        children: [
          if (_status.isNotEmpty)
            Padding(
              padding: const EdgeInsets.all(8),
              child: Text(_status, key: const Key('emergencyStatus')),
            ),
          Expanded(
            child: _contacts.isEmpty
                ? const Center(child: Text('No emergency contacts yet.'))
                : ListView.builder(
                    itemCount: _contacts.length,
                    itemBuilder: (ctx, i) {
                      final c = _contacts[i];
                      return ListTile(
                        key: Key('contact-${c.id}'),
                        title: Text(c.contactEmail),
                        subtitle: Text(c.state == 'pending' && c.unlockAt != null
                            ? 'Requested access — releases ${c.unlockAt}'
                            : c.state),
                        trailing: c.state == 'pending'
                            ? TextButton(
                                key: Key('deny-${c.id}'),
                                onPressed: _busy ? null : () => _deny(c),
                                child: const Text('Deny'),
                              )
                            : null,
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
