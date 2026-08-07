import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultkeep_mobile/core/biometric.dart';
import 'package:vaultkeep_mobile/core/local_store.dart';
import 'package:vaultkeep_mobile/core/vault_app.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';
import 'package:vaultkeep_mobile/ui/biometric_unlock_screen.dart';
import 'package:vaultkeep_mobile/ui/vault_screen.dart';

import 'biometric_test.dart' show MockEnclave, MemoryTokenStore;

const fastKdf = KdfParams(memoryKiB: 256, iterations: 1, parallelism: 1);
const salt = 'q83vASNFZ4mrze8BI0VniQ==';

void main() {
  testWidgets('vault screen: enabling biometrics enrolls the live key',
      (tester) async {
    final enclave = MockEnclave();
    final tokens = MemoryTokenStore();
    final bio = BiometricUnlock(enclave, tokens);
    final vault = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
    await vault.unlock('widget test pw');

    await tester.pumpWidget(MaterialApp(
      home: VaultScreen(
        vault: vault,
        email: 'me@x.com',
        userId: 'user-1',
        biometric: bio,
        onLock: () {},
      ),
    ));
    await tester.pumpAndSettle();

    expect(await bio.isEnrolled(), false);
    await tester.tap(find.byKey(const Key('bioToggleBtn')));
    await tester.pumpAndSettle();

    expect(await bio.isEnrolled(), true);
    expect(find.text('Biometric unlock enabled'), findsOneWidget);

    await tester.tap(find.byKey(const Key('bioToggleBtn')));
    await tester.pumpAndSettle();
    expect(await bio.isEnrolled(), false);
    expect(find.text('Biometric unlock disabled'), findsOneWidget);
  });

  testWidgets('vault screen: no biometric instance means no toggle button',
      (tester) async {
    final vault = VaultApp(salt, MemoryStore(), null, kdf: fastKdf);
    await vault.unlock('widget test pw');

    await tester.pumpWidget(MaterialApp(
      home: VaultScreen(vault: vault, email: 'me@x.com', onLock: () {}),
    ));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('bioToggleBtn')), findsNothing);
  });

  testWidgets(
      'biometric unlock screen: declined prompt shows a status and falls back to password',
      (tester) async {
    final enclave = MockEnclave()..promptResult = false;
    final tokens = MemoryTokenStore()..token = 'anything-nonnull';
    final bio = BiometricUnlock(enclave, tokens);
    var usedPassword = false;

    await tester.pumpWidget(MaterialApp(
      home: BiometricUnlockScreen(
        biometric: bio,
        onUnlocked: (_) async {},
        onUsePassword: () => usedPassword = true,
      ),
    ));
    await tester.pumpAndSettle();

    expect(find.text('Biometric unlock unavailable or declined.'),
        findsOneWidget);

    await tester.tap(find.byKey(const Key('bioUsePassword')));
    await tester.pumpAndSettle();
    expect(usedPassword, true);
  });

  testWidgets('biometric unlock screen: a successful prompt calls onUnlocked',
      (tester) async {
    final enclave = MockEnclave();
    final tokens = MemoryTokenStore();
    final bio = BiometricUnlock(enclave, tokens);
    await bio.enroll(
        Uint8List.fromList(List.generate(32, (_) => 7)), salt, 'user-1', 'me@x.com');
    RecoveredKey? unlocked;

    await tester.pumpWidget(MaterialApp(
      home: BiometricUnlockScreen(
        biometric: bio,
        onUnlocked: (r) async => unlocked = r,
        onUsePassword: () {},
      ),
    ));
    await tester.pumpAndSettle();

    expect(unlocked, isNotNull);
    expect(unlocked!.userId, 'user-1');
    expect(unlocked!.email, 'me@x.com');
  });
}
