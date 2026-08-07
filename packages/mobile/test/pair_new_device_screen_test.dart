import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vaultkeep_mobile/core/auth_client.dart';
import 'package:vaultkeep_mobile/core/devicekeys.dart';
import 'package:vaultkeep_mobile/core/vault_crypto.dart';
import 'package:vaultkeep_mobile/ui/pair_new_device_screen.dart';

Future<Session> _pendingSession() async {
  final signing = await generateSigningKeys();
  final exchange = await generateExchangeKeys();
  return Session(
    token: 'tok',
    userId: 'u1',
    email: 'me@x.com',
    saltB64: 'q83vASNFZ4mrze8BI0VniQ==',
    kdf: KdfParams.defaults,
    key: Uint8List(32),
    device: DeviceIdentity(
      deviceId: 'phone-1',
      name: 'Mobile',
      signingPublicKey: signing.publicKey,
      signingPrivateKey: signing.privateKey,
      exchangePublicKey: exchange.publicKey,
      exchangePrivateKey: exchange.privateKey,
    ),
  );
}

void main() {
  testWidgets('shows a QR code and calls onApproved once /devices returns 200',
      (tester) async {
    var approved = false;
    var stillPending = true;
    final client = MockClient((req) async {
      if (req.url.path == '/devices') {
        return stillPending
            ? http.Response(jsonEncode({'error': 'device not approved'}), 403)
            : http.Response(jsonEncode({'devices': []}), 200);
      }
      return http.Response('{}', 404);
    });

    await tester.pumpWidget(MaterialApp(
      home: PairNewDeviceScreen(
        baseUrl: 'http://x',
        session: await _pendingSession(),
        onApproved: () => approved = true,
        onSkip: () {},
        httpClient: client,
      ),
    ));
    await tester.pump();
    await tester.pump();

    expect(find.byKey(const Key('pairQr')), findsOneWidget);
    expect(approved, false);

    stillPending = false;
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(approved, true);

    // Unmount so the polling/refresh Timers get cancelled in dispose() —
    // otherwise flutter_test flags them as leaked at the end of the test.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('the skip button lets the user defer approval', (tester) async {
    var skipped = false;
    final client = MockClient(
        (req) async => http.Response(jsonEncode({'error': 'pending'}), 403));

    await tester.pumpWidget(MaterialApp(
      home: PairNewDeviceScreen(
        baseUrl: 'http://x',
        session: await _pendingSession(),
        onApproved: () {},
        onSkip: () => skipped = true,
        httpClient: client,
      ),
    ));
    await tester.pump();
    await tester.pump();

    await tester.tap(find.byKey(const Key('pairSkip')));
    expect(skipped, true);

    await tester.pumpWidget(const SizedBox());
  });
}
