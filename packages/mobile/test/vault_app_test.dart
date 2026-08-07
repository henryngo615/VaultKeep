import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultkeep_mobile/core/local_store.dart';
import 'package:vaultkeep_mobile/core/sync_client.dart';
import 'package:vaultkeep_mobile/core/vault_app.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';

// Fast KDF for tests — algorithm identical, cost turned down.
const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);
const salt = 'q83vASNFZ4mrze8BI0VniQ==';

/// In-memory server double implementing the real optimistic-concurrency
/// contract (baseVersion must match, conflicts return the server copy).
class FakeServer implements Transport {
  final Map<String, RemoteItem> rows = {};
  @override
  Future<List<RemoteItem>> pull({String? since}) async => rows.values.toList();
  @override
  Future<PushOutcome> push(String id, String ciphertext, int? baseVersion) async {
    final cur = rows[id];
    final curVersion = cur?.version ?? 0;
    if ((baseVersion ?? 0) != curVersion) {
      return PushOutcome(status: 'conflict', server: cur);
    }
    final next = RemoteItem(
        id: id,
        ciphertext: ciphertext,
        version: curVersion + 1,
        updatedAt: DateTime.now().toIso8601String());
    rows[id] = next;
    return PushOutcome(status: 'ok', version: next.version);
  }
}

void main() {
  test('unlock → add → lock → reopen with the same password', () async {
    final store = MemoryStore();
    final a = VaultApp(salt, store, null, kdf: fastKdf);
    await a.unlock('master pw 1');
    await a.add(title: 'GitHub', username: 'henry', password: 'gh-secret');
    a.lock();
    expect(() => a.list(), throwsStateError);

    final b = VaultApp(salt, store, null, kdf: fastKdf);
    await b.unlock('master pw 1');
    expect(b.list().single.password, 'gh-secret');
  });

  test('a wrong password fails via the GCM auth tag', () async {
    final store = MemoryStore();
    final a = VaultApp(salt, store, null, kdf: fastKdf);
    await a.unlock('right password');
    await a.add(title: 'X', password: 'p');
    a.lock();

    final b = VaultApp(salt, store, null, kdf: fastKdf);
    expect(() => b.unlock('wrong password'),
        throwsA(isA<SecretBoxAuthenticationError>()));
    expect(b.isUnlocked, false);
  });

  test('the on-disk blob is one opaque ciphertext — no plaintext leaks',
      () async {
    final store = MemoryStore();
    final a = VaultApp(salt, store, null, kdf: fastKdf);
    await a.unlock('master pw 1');
    await a.add(title: 'Proton', username: 'henry', password: 'super-secret');
    final raw = (await store.readRaw())!;
    expect(raw, isNot(contains('Proton')));
    expect(raw, isNot(contains('super-secret')));
    expect(() => jsonDecode(raw), throwsFormatException); // base64, not JSON
  });

  test('two-way sync: push, pull on a second device, conflict adopts server',
      () async {
    final server = FakeServer();

    final phone = VaultApp(salt, MemoryStore(), server, kdf: fastKdf);
    await phone.unlock('shared pw');
    final item = await phone.add(title: 'Bank', password: 'v1');
    expect((await phone.sync()).pushed, 1);

    // A second device pulls the item and edits it FIRST (wins the race).
    final laptop = VaultApp(salt, MemoryStore(), server, kdf: fastKdf);
    await laptop.unlock('shared pw');
    expect((await laptop.sync()).pulled, 1);
    await laptop.update(item.id, password: 'v2-from-laptop');
    expect((await laptop.sync()).pushed, 1); // server now at version 2

    // The phone edits the same item from its stale version → conflict →
    // the server's newer copy is adopted (same policy as desktop).
    await phone.update(item.id, password: 'v2-from-phone');
    await phone.add(title: 'Unrelated', password: 'x');
    final s = await phone.sync();
    expect(s.conflicts, 1);
    expect(s.pushed, 1); // the unrelated new item still went up
    expect(phone.list().firstWhere((i) => i.id == item.id).password,
        'v2-from-laptop');

    // Everyone converges after one more pull.
    await laptop.sync();
    expect(laptop.list().length, 2);
  });

  test('snapshotKey returns an independent copy of the live master key',
      () async {
    final app = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
    final key = await deriveMasterKey('pw', salt, fastKdf);
    await app.unlockWithKey(key);
    final snapshot = app.snapshotKey();
    expect(snapshot, key);
    snapshot.fillRange(0, snapshot.length, 0);
    // Mutating the snapshot must not zero the vault's own live key.
    expect(key.every((b) => b == 0), false);
  });

  group('rekey (recovery-key password reset)', () {
    test(
        're-encrypts the local blob and re-pushes every item under the new key',
        () async {
      final server = FakeServer();
      final store = MemoryStore();
      final app = VaultApp(salt, store, server, kdf: fastKdf);
      await app.unlock('old password');
      final item =
          await app.add(title: 'GitHub', username: 'henry', password: 'gh-secret');
      await app.sync();
      final versionBefore = server.rows[item.id]!.version;

      final newKey = await deriveMasterKey('new password', salt, fastKdf);
      await app.rekey(newKey);

      // The item was marked dirty by rekey, so syncing again re-pushes it —
      // the server's old copy is ciphertext under a key nobody has anymore.
      final s = await app.sync();
      expect(s.pushed, 1);
      expect(server.rows[item.id]!.version, greaterThan(versionBefore));

      // A fresh app unlocked with the NEW key reads the same item back.
      final reopened = VaultApp(salt, store, server, kdf: fastKdf);
      await reopened.unlockWithKey(newKey);
      expect(reopened.list().single.password, 'gh-secret');

      // The OLD password can no longer open the (now re-keyed) local blob.
      final stale = VaultApp(salt, store, server, kdf: fastKdf);
      expect(() => stale.unlock('old password'),
          throwsA(isA<SecretBoxAuthenticationError>()));
    });

    test('rekeying a locked vault throws', () async {
      final app = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
      final key = await deriveMasterKey('x', salt, fastKdf);
      expect(() => app.rekey(key), throwsStateError);
    });

    test('rejects a malformed replacement key', () async {
      final app = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
      await app.unlock('pw');
      expect(() => app.rekey(Uint8List(16)), throwsArgumentError);
    });
  });
}
