import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultkeep_mobile/core/local_store.dart';
import 'package:vaultkeep_mobile/core/vault_app.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';
import 'package:vaultkeep_mobile/ui/vault_screen.dart';

const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);
const salt = 'q83vASNFZ4mrze8BI0VniQ==';

Future<VaultApp> unlockedVault() async {
  final app = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
  await app.unlock('widget test pw');
  await app.add(title: 'GitHub', username: 'henry', password: 'gh-secret');
  await app.add(title: 'Bank', username: 'h@x.com', password: 'bank-secret');
  return app;
}

void main() {
  testWidgets('vault list shows decrypted items and search filters them',
      (tester) async {
    var locked = false;
    await tester.pumpWidget(MaterialApp(
      home: VaultScreen(
        vault: await unlockedVault(),
        email: 'me@x.com',
        onLock: () => locked = true,
      ),
    ));
    await tester.pumpAndSettle();

    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('Bank'), findsOneWidget);
    // Passwords are not rendered while collapsed.
    expect(find.text('gh-secret'), findsNothing);

    await tester.enterText(find.byKey(const Key('search')), 'git');
    await tester.pumpAndSettle();
    expect(find.text('GitHub'), findsOneWidget);
    expect(find.text('Bank'), findsNothing);

    await tester.tap(find.byKey(const Key('lockBtn')));
    expect(locked, true);
  });

  testWidgets('reveal shows a password only after an explicit tap',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: VaultScreen(
          vault: await unlockedVault(), email: 'me@x.com', onLock: () {}),
    ));
    await tester.pumpAndSettle();

    await tester.tap(find.text('GitHub'));
    await tester.pumpAndSettle();
    expect(find.text('gh-secret'), findsNothing); // masked by default

    await tester.tap(find.byIcon(Icons.visibility).first);
    await tester.pumpAndSettle();
    expect(find.text('gh-secret'), findsOneWidget);
  });

  testWidgets('add flow: sheet → save → item appears (encrypted at rest)',
      (tester) async {
    final store = MemoryStore();
    final app = VaultApp(salt, store, null, kdf: fastKdf);
    await app.unlock('widget test pw');

    await tester.pumpWidget(MaterialApp(
      home: VaultScreen(vault: app, email: 'me@x.com', onLock: () {}),
    ));
    await tester.pumpAndSettle();
    expect(find.textContaining('vault is empty'), findsOneWidget);

    await tester.tap(find.byKey(const Key('addBtn')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('addTitle')), 'Proton');
    await tester.enterText(find.byKey(const Key('addUser')), 'henry');
    await tester.tap(find.byKey(const Key('genBtn'))); // generator fills pw
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('saveItem')));
    await tester.pumpAndSettle();

    expect(find.text('Proton'), findsOneWidget);
    expect(app.list().single.password, isNotNull);
    expect(app.list().single.password!.length, 20);

    // What hit the store is ciphertext.
    final raw = (await store.readRaw())!;
    expect(raw, isNot(contains('Proton')));
  });
}
