import 'package:flutter_test/flutter_test.dart';
import 'package:vaultkeep_mobile/core/devicekeys.dart';
import 'package:vaultkeep_mobile/core/pairing.dart';

void main() {
  test('a created payload self-verifies and round-trips through encode/decode',
      () async {
    final keys = await generateSigningKeys();
    final payload = await createPairingPayload(
      userId: 'u1',
      deviceId: 'dev-1',
      name: 'Mobile',
      signingPrivateKeyB64: keys.privateKey,
    );

    expect(payload.isExpired, false);
    expect(await verifyMessage(keys.publicKey, payload.signedMessage, payload.signature),
        true);

    final decoded = PairingPayload.decode(payload.encode());
    expect(decoded.userId, 'u1');
    expect(decoded.deviceId, 'dev-1');
    expect(decoded.name, 'Mobile');
    expect(decoded.signature, payload.signature);
    expect(decoded.expiresAt, payload.expiresAt);
  });

  test('an expired payload reports isExpired', () async {
    final keys = await generateSigningKeys();
    final payload = await createPairingPayload(
      userId: 'u1',
      deviceId: 'dev-1',
      name: 'Mobile',
      signingPrivateKeyB64: keys.privateKey,
      ttl: const Duration(seconds: -1),
    );
    expect(payload.isExpired, true);
  });

  test('decode rejects non-JSON input', () {
    expect(() => PairingPayload.decode('not json at all'),
        throwsFormatException);
  });

  test('decode rejects an unsupported version', () {
    expect(
      () => PairingPayload.decode(
          '{"v":99,"userId":"u","deviceId":"d","name":"n","exp":1,"sig":"s"}'),
      throwsFormatException,
    );
  });

  test('decode rejects missing fields', () {
    expect(() => PairingPayload.decode('{"v":1,"userId":"u"}'),
        throwsFormatException);
  });

  test('a tampered signature no longer verifies against the original message',
      () async {
    final keys = await generateSigningKeys();
    final payload = await createPairingPayload(
      userId: 'u1',
      deviceId: 'dev-1',
      name: 'Mobile',
      signingPrivateKeyB64: keys.privateKey,
    );
    final tampered = payload.encode().replaceFirst(payload.deviceId, 'dev-evil');
    final decoded = PairingPayload.decode(tampered);
    expect(
      await verifyMessage(keys.publicKey, decoded.signedMessage, decoded.signature),
      false,
    );
  });
}
