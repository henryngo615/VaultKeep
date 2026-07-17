import 'dart:convert';

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
}
