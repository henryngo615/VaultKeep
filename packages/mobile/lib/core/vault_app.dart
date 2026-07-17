import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'local_store.dart';
import 'sync_client.dart';
import 'vault_crypto.dart';

/// One vault item — mirrors `@vaultkeep/shared`'s VaultItem.
class VaultItem {
  final String id;
  final String type;
  String title;
  String? username;
  String? password;
  String? url;
  final String createdAt;
  String updatedAt;

  VaultItem({
    required this.id,
    this.type = 'login',
    required this.title,
    this.username,
    this.password,
    this.url,
    required this.createdAt,
    required this.updatedAt,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'tags': const <String>[],
        'fields': const <String, String>{},
        'favorite': false,
        'createdAt': createdAt,
        'updatedAt': updatedAt,
      };

  factory VaultItem.fromJson(Map<String, dynamic> j) => VaultItem(
        id: j['id'] as String,
        type: (j['type'] ?? 'login') as String,
        title: (j['title'] ?? 'Untitled') as String,
        username: j['username'] as String?,
        password: j['password'] as String?,
        url: j['url'] as String?,
        createdAt: (j['createdAt'] ?? '') as String,
        updatedAt: (j['updatedAt'] ?? '') as String,
      );
}

class SyncSummary {
  final int pushed;
  final int pulled;
  final int conflicts;
  SyncSummary(this.pushed, this.pulled, this.conflicts);
}

class _Meta {
  int version;
  bool dirty;
  _Meta(this.version, this.dirty);
}

/// The mobile app's controller — a Dart mirror of the desktop `VaultApp`.
/// The ONLY place that holds the decrypted master key and plaintext items;
/// everything persisted (locally or to the server) is ciphertext.
///
/// Lifecycle: construct → unlock(masterPassword) → use → lock().
class VaultApp {
  final String saltB64;
  final LocalStore store;
  final Transport? transport;
  final KdfParams kdf;

  Uint8List? _key;
  final Map<String, VaultItem> _items = {};
  final Map<String, _Meta> _meta = {};

  VaultApp(this.saltB64, this.store, this.transport,
      {this.kdf = KdfParams.defaults});

  bool get isUnlocked => _key != null;

  /// Derive the master key and decrypt the local vault into memory.
  /// A wrong password makes [decryptBlob] throw (GCM auth tag).
  Future<void> unlock(String masterPassword) async {
    await unlockWithKey(await deriveMasterKey(masterPassword, saltB64, kdf));
  }

  /// Unlock with an already-derived key (fresh from [AuthClient.login], or a
  /// future biometric unwrap). Same GCM gate as the password path.
  Future<void> unlockWithKey(Uint8List key) async {
    if (key.length != 32) throw ArgumentError('master key must be 32 bytes');
    final raw = await store.readRaw();
    if (raw != null) {
      final state = jsonDecode(await decryptBlob(key, raw));
      for (final it in (state['items'] as List<dynamic>)) {
        final item = VaultItem.fromJson(it as Map<String, dynamic>);
        _items[item.id] = item;
      }
      for (final m in (state['meta'] as List<dynamic>)) {
        _meta[m['id'] as String] =
            _Meta(m['version'] as int, m['dirty'] as bool);
      }
    }
    _key = key;
  }

  /// Wipe the key and plaintext from memory.
  void lock() {
    if (_key != null) zeroKey(_key!);
    _key = null;
    _items.clear();
    _meta.clear();
  }

  List<VaultItem> list() {
    _requireKey();
    final all = _items.values.toList()
      ..sort((a, b) => a.title.toLowerCase().compareTo(b.title.toLowerCase()));
    return all;
  }

  Future<VaultItem> add({
    required String title,
    String? username,
    String? password,
    String? url,
  }) async {
    _requireKey();
    final now = DateTime.now().toUtc().toIso8601String();
    final item = VaultItem(
      id: _uuid(),
      title: title,
      username: username,
      password: password,
      url: url,
      createdAt: now,
      updatedAt: now,
    );
    _items[item.id] = item;
    _meta[item.id] = _Meta(0, true);
    await _persist();
    return item;
  }

  /// Edit an existing item and mark it for sync.
  Future<VaultItem> update(
    String id, {
    String? title,
    String? username,
    String? password,
    String? url,
  }) async {
    _requireKey();
    final cur = _items[id];
    if (cur == null) throw ArgumentError('no item $id');
    if (title != null) cur.title = title;
    if (username != null) cur.username = username;
    if (password != null) cur.password = password;
    if (url != null) cur.url = url;
    cur.updatedAt = DateTime.now().toUtc().toIso8601String();
    _meta[id]!.dirty = true;
    await _persist();
    return cur;
  }

  /// Two-way sync: push dirty items, then pull and merge remote changes.
  /// Conflicts adopt the server's newer copy (same policy as desktop).
  Future<SyncSummary> sync() async {
    _requireKey();
    final t = transport;
    if (t == null) throw StateError('offline: no transport configured');
    var pushed = 0, pulled = 0, conflicts = 0;

    for (final entry in _meta.entries.toList()) {
      final m = entry.value;
      if (!m.dirty) continue;
      final item = _items[entry.key]!;
      final blob = await encryptBlob(_key!, jsonEncode(item.toJson()));
      final out =
          await t.push(entry.key, blob, m.version == 0 ? null : m.version);
      if (out.ok) {
        _meta[entry.key] = _Meta(out.version!, false);
        pushed++;
      } else {
        conflicts++;
        final server = out.server;
        if (server != null) {
          final remote = VaultItem.fromJson(
              jsonDecode(await decryptBlob(_key!, server.ciphertext))
                  as Map<String, dynamic>);
          _items[entry.key] = remote;
          _meta[entry.key] = _Meta(server.version, false);
        }
      }
    }

    for (final r in await t.pull()) {
      final known = _meta[r.id];
      if (known == null || r.version > known.version) {
        _items[r.id] = VaultItem.fromJson(
            jsonDecode(await decryptBlob(_key!, r.ciphertext))
                as Map<String, dynamic>);
        _meta[r.id] = _Meta(r.version, false);
        pulled++;
      }
    }

    await _persist();
    return SyncSummary(pushed, pulled, conflicts);
  }

  Future<void> _persist() async {
    final key = _requireKey();
    final state = jsonEncode({
      'items': _items.values.map((i) => i.toJson()).toList(),
      'meta': _meta.entries
          .map((e) =>
              {'id': e.key, 'version': e.value.version, 'dirty': e.value.dirty})
          .toList(),
    });
    // The ENTIRE state is encrypted as one blob — ids and metadata included.
    await store.writeRaw(await encryptBlob(key, state));
  }

  Uint8List _requireKey() {
    final k = _key;
    if (k == null) throw StateError('vault is locked');
    return k;
  }
}

/// Strong random password generator (CSPRNG).
String generatePassword({int length = 20}) {
  const sets =
      'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#\$%^&*-_=+?';
  final rng = Random.secure();
  return List.generate(length, (_) => sets[rng.nextInt(sets.length)]).join();
}

String _uuid() {
  final rng = Random.secure();
  final b = List<int>.generate(16, (_) => rng.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final h = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
}
