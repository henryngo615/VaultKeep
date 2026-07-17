// Live interop check against a running sync server (no Flutter needed):
//
//   dart run tool/live_check.dart <serverUrl> <email> <password> <totpCode>
//
// Signs in with the shared zero-knowledge flow (self-enrolling this process
// as the account's first device), pushes one item encrypted by the DART
// crypto, then pulls it back. The node-side driver decrypts the stored blob
// with @vaultkeep/crypto to prove cross-implementation compatibility.
import 'dart:io';

import 'package:vaultkeep_mobile/core/auth_client.dart';
import 'package:vaultkeep_mobile/core/local_store.dart';
import 'package:vaultkeep_mobile/core/sync_client.dart';
import 'package:vaultkeep_mobile/core/vault_app.dart';

Future<void> main(List<String> args) async {
  final [server, email, password, code] = args;
  final auth = AuthClient(server, MemoryDeviceStore());

  final session = await auth.login(email, password, code);
  stdout.writeln('DART: signed in, userId=${session.userId}');

  final vault = VaultApp(
    session.saltB64,
    MemoryStore(),
    HttpTransport(server, session.token),
    kdf: session.kdf,
  );
  await vault.unlockWithKey(session.key);
  await vault.add(
      title: 'From Dart', username: 'henry', password: 'dart-encrypted-pw!');
  final s = await vault.sync();
  stdout.writeln('DART: pushed ${s.pushed} item(s)');

  // Fresh pull into a new VaultApp proves the round trip server-side.
  final again = VaultApp(
    session.saltB64,
    MemoryStore(),
    HttpTransport(server, session.token),
    kdf: session.kdf,
  );
  await again.unlock(password);
  await again.sync();
  final item = again.list().single;
  if (item.title != 'From Dart' || item.password != 'dart-encrypted-pw!') {
    stderr.writeln('DART: round-trip mismatch');
    exit(1);
  }
  stdout.writeln('DART: fresh unlock + pull decrypted the item OK');
  exit(0);
}
