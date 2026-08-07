import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/biometric.dart';
import '../core/vault_app.dart';
import '../core/vault_crypto.dart' show zeroKey;

/// The unlocked vault: search, list, item detail (copy/reveal), add sheet
/// with a generator, manual sync, lock. Pure UI over the tested core.
class VaultScreen extends StatefulWidget {
  final VaultApp vault;
  final String email;
  final VoidCallback onLock;
  /// Opens the QR scanner to approve a new device. Omitted for sessions that
  /// can't approve anyone (no live token — e.g. an offline biometric unlock).
  final VoidCallback? onScanToApprove;
  /// Opens recovery-key setup / emergency-contact management. Both need a
  /// live token, so both are omitted together for offline sessions.
  final VoidCallback? onOpenRecoverySetup;
  final VoidCallback? onOpenEmergencyContacts;
  /// Enables the biometric enroll/unenroll toggle when provided (offline
  /// biometric-unlocked sessions have no fresh [userId] to enroll, so callers
  /// may omit [biometric] there).
  final BiometricUnlock? biometric;
  final String? userId;
  const VaultScreen({
    super.key,
    required this.vault,
    required this.email,
    required this.onLock,
    this.onScanToApprove,
    this.onOpenRecoverySetup,
    this.onOpenEmergencyContacts,
    this.biometric,
    this.userId,
  });

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  String _filter = '';
  String _status = '';
  bool _bioEnrolled = false;

  @override
  void initState() {
    super.initState();
    widget.biometric?.isEnrolled().then((v) {
      if (mounted) setState(() => _bioEnrolled = v);
    });
  }

  Future<void> _toggleBiometric() async {
    final bio = widget.biometric;
    if (bio == null) return;
    if (_bioEnrolled) {
      await bio.unenroll();
      setState(() {
        _bioEnrolled = false;
        _status = 'Biometric unlock disabled';
      });
      return;
    }
    final key = widget.vault.snapshotKey();
    try {
      await bio.enroll(key, widget.vault.saltB64, widget.userId, widget.email);
      setState(() {
        _bioEnrolled = true;
        _status = 'Biometric unlock enabled';
      });
    } catch (_) {
      setState(() => _status = 'Biometric unlock unavailable on this device');
    } finally {
      zeroKey(key);
    }
  }

  List<VaultItem> get _items {
    final q = _filter.trim().toLowerCase();
    final all = widget.vault.list();
    if (q.isEmpty) return all;
    return all
        .where((i) =>
            i.title.toLowerCase().contains(q) ||
            (i.username ?? '').toLowerCase().contains(q) ||
            (i.url ?? '').toLowerCase().contains(q))
        .toList();
  }

  Future<void> _sync() async {
    setState(() => _status = 'Syncing…');
    try {
      final s = await widget.vault.sync();
      setState(() => _status = 'Synced ↑${s.pushed} ↓${s.pulled}'
          '${s.conflicts > 0 ? ' ⚠${s.conflicts}' : ''}');
    } catch (_) {
      setState(() => _status = 'Offline');
    }
  }

  Future<void> _addSheet() async {
    final title = TextEditingController();
    final user = TextEditingController();
    final url = TextEditingController();
    final pass = TextEditingController();
    final added = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(
          left: 16, right: 16, top: 16,
          bottom: MediaQuery.of(ctx).viewInsets.bottom + 16,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Add item', style: Theme.of(ctx).textTheme.titleLarge),
            const SizedBox(height: 12),
            TextField(
                key: const Key('addTitle'),
                controller: title,
                decoration: const InputDecoration(labelText: 'Title')),
            const SizedBox(height: 8),
            TextField(
                key: const Key('addUser'),
                controller: user,
                decoration:
                    const InputDecoration(labelText: 'Username or email')),
            const SizedBox(height: 8),
            TextField(
                controller: url,
                decoration: const InputDecoration(labelText: 'Website URL')),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(
                child: TextField(
                    key: const Key('addPass'),
                    controller: pass,
                    decoration: const InputDecoration(labelText: 'Password')),
              ),
              IconButton(
                key: const Key('genBtn'),
                tooltip: 'Generate strong password',
                icon: const Text('🎲', style: TextStyle(fontSize: 20)),
                onPressed: () => pass.text = generatePassword(),
              ),
            ]),
            const SizedBox(height: 16),
            FilledButton(
              key: const Key('saveItem'),
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Save to vault'),
            ),
          ],
        ),
      ),
    );
    if (added == true && title.text.trim().isNotEmpty) {
      await widget.vault.add(
        title: title.text.trim(),
        username: user.text.trim().isEmpty ? null : user.text.trim(),
        password: pass.text.isEmpty ? null : pass.text,
        url: url.text.trim().isEmpty ? null : url.text.trim(),
      );
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final items = _items;
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.email, style: const TextStyle(fontSize: 14)),
        actions: [
          if (widget.onScanToApprove != null)
            IconButton(
                key: const Key('scanToApproveBtn'),
                tooltip: 'Approve a device',
                onPressed: widget.onScanToApprove,
                icon: const Icon(Icons.qr_code_scanner)),
          if (widget.onOpenRecoverySetup != null || widget.onOpenEmergencyContacts != null)
            PopupMenuButton<String>(
              key: const Key('accountMenu'),
              onSelected: (v) {
                if (v == 'recovery') widget.onOpenRecoverySetup?.call();
                if (v == 'emergency') widget.onOpenEmergencyContacts?.call();
              },
              itemBuilder: (ctx) => [
                if (widget.onOpenRecoverySetup != null)
                  const PopupMenuItem(
                      key: Key('recoveryMenuItem'),
                      value: 'recovery',
                      child: Text('Recovery key')),
                if (widget.onOpenEmergencyContacts != null)
                  const PopupMenuItem(
                      key: Key('emergencyMenuItem'),
                      value: 'emergency',
                      child: Text('Emergency contacts')),
              ],
            ),
          if (widget.biometric != null)
            IconButton(
                key: const Key('bioToggleBtn'),
                tooltip: _bioEnrolled
                    ? 'Disable biometric unlock'
                    : 'Enable biometric unlock',
                onPressed: _toggleBiometric,
                icon: Icon(Icons.fingerprint,
                    color: _bioEnrolled ? const Color(0xFF8B5CF6) : null)),
          IconButton(
              key: const Key('syncBtn'),
              tooltip: 'Sync',
              onPressed: _sync,
              icon: const Icon(Icons.sync)),
          IconButton(
              key: const Key('lockBtn'),
              tooltip: 'Lock',
              onPressed: widget.onLock,
              icon: const Icon(Icons.lock)),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(64),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: TextField(
              key: const Key('search'),
              decoration: const InputDecoration(
                hintText: 'Search vault…',
                prefixIcon: Icon(Icons.search),
                isDense: true,
              ),
              onChanged: (v) => setState(() => _filter = v),
            ),
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        key: const Key('addBtn'),
        onPressed: _addSheet,
        child: const Icon(Icons.add),
      ),
      body: Column(children: [
        if (_status.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(_status,
                key: const Key('syncStatus'),
                style: const TextStyle(color: Color(0xFF8B93A3), fontSize: 12)),
          ),
        Expanded(
          child: items.isEmpty
              ? const Center(
                  child: Text('🗝️  Your vault is empty.',
                      style: TextStyle(color: Color(0xFF8B93A3))))
              : ListView.builder(
                  itemCount: items.length,
                  itemBuilder: (ctx, i) => _ItemTile(item: items[i]),
                ),
        ),
      ]),
    );
  }
}

class _ItemTile extends StatefulWidget {
  final VaultItem item;
  const _ItemTile({required this.item});
  @override
  State<_ItemTile> createState() => _ItemTileState();
}

class _ItemTileState extends State<_ItemTile> {
  bool _revealed = false;

  Color get _avatarColor {
    const colors = [
      Color(0xFF6366F1), Color(0xFF8B5CF6), Color(0xFFEC4899), Color(0xFFF59E0B),
      Color(0xFF10B981), Color(0xFF06B6D4), Color(0xFFEF4444), Color(0xFF3B82F6),
    ];
    var h = 0;
    for (final c in widget.item.title.codeUnits) {
      h = (h * 31 + c) & 0x7fffffff;
    }
    return colors[h % colors.length];
  }

  Future<void> _copy(String label, String? value) async {
    await Clipboard.setData(ClipboardData(text: value ?? ''));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('$label copied')));
  }

  @override
  Widget build(BuildContext context) {
    final it = widget.item;
    return ExpansionTile(
      leading: CircleAvatar(
        backgroundColor: _avatarColor,
        child: Text(it.title.isEmpty ? '?' : it.title[0].toUpperCase(),
            style: const TextStyle(color: Colors.white)),
      ),
      title: Text(it.title),
      subtitle: Text(it.username ?? it.url ?? it.type,
          style: const TextStyle(fontSize: 12)),
      children: [
        ListTile(
          dense: true,
          title: Text(it.username ?? '—'),
          subtitle: const Text('Username'),
          trailing: IconButton(
              icon: const Icon(Icons.copy, size: 18),
              onPressed: () => _copy('Username', it.username)),
        ),
        ListTile(
          dense: true,
          title: Text(_revealed ? (it.password ?? '—') : '••••••••••'),
          subtitle: const Text('Password'),
          trailing: Row(mainAxisSize: MainAxisSize.min, children: [
            IconButton(
                icon: Icon(_revealed ? Icons.visibility_off : Icons.visibility,
                    size: 18),
                onPressed: () => setState(() => _revealed = !_revealed)),
            IconButton(
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () => _copy('Password', it.password)),
          ]),
        ),
        if (it.url != null)
          ListTile(dense: true, title: Text(it.url!), subtitle: const Text('Website')),
      ],
    );
  }
}
