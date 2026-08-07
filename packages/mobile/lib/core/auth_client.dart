import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'devicekeys.dart' as devicekeys;
import 'vault_crypto.dart';

/// Zero-knowledge auth against the sync server — same flow as web/extension:
/// `/auth/kdf` → derive key + verifier locally (the password never leaves the
/// device) → login (self-enrolling this phone as a device on first use, via
/// the `needsDevice` handshake) → TOTP → full token.
class Session {
  final String token;
  final String userId;
  final String email;
  final String saltB64;
  final KdfParams kdf;
  final Uint8List key;
  /// This device's own identity — needed to show a QR pairing code for
  /// itself while pending, or to sign approvals for OTHER devices once this
  /// one is trusted.
  final DeviceIdentity device;
  Session({
    required this.token,
    required this.userId,
    required this.email,
    required this.saltB64,
    required this.kdf,
    required this.key,
    required this.device,
  });
}

class AuthException implements Exception {
  final String message;
  AuthException(this.message);
  @override
  String toString() => message;
}

/// This device's enrollment: the server-assigned id plus the REAL X25519/
/// Ed25519 keypairs generated at enrollment time. The private halves never
/// leave the device — persisted locally (see `DeviceStore`) so this device
/// can later sign `approve-device:<id>` for a new device it trusts (QR
/// pairing), the same way desktop's `DeviceIdentity` works.
class DeviceIdentity {
  final String deviceId;
  final String name;
  final String signingPublicKey;
  final String signingPrivateKey;
  final String exchangePublicKey;
  final String exchangePrivateKey;
  DeviceIdentity({
    required this.deviceId,
    required this.name,
    required this.signingPublicKey,
    required this.signingPrivateKey,
    required this.exchangePublicKey,
    required this.exchangePrivateKey,
  });

  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'name': name,
        'signingPublicKey': signingPublicKey,
        'signingPrivateKey': signingPrivateKey,
        'exchangePublicKey': exchangePublicKey,
        'exchangePrivateKey': exchangePrivateKey,
      };
  factory DeviceIdentity.fromJson(Map<String, dynamic> j) => DeviceIdentity(
        deviceId: j['deviceId'] as String,
        name: j['name'] as String,
        signingPublicKey: j['signingPublicKey'] as String,
        signingPrivateKey: j['signingPrivateKey'] as String,
        exchangePublicKey: j['exchangePublicKey'] as String,
        exchangePrivateKey: j['exchangePrivateKey'] as String,
      );
}

/// Persists this phone's device identity (id + keys) per email.
abstract class DeviceStore {
  Future<DeviceIdentity?> load(String email);
  Future<void> save(String email, DeviceIdentity identity);
}

class MemoryDeviceStore implements DeviceStore {
  final Map<String, DeviceIdentity> _m = {};
  @override
  Future<DeviceIdentity?> load(String email) async => _m[email.toLowerCase()];
  @override
  Future<void> save(String email, DeviceIdentity identity) async =>
      _m[email.toLowerCase()] = identity;
}

class RegistrationStart {
  final String userId;
  final String totpSecret;
  final String otpauthUri;
  RegistrationStart(this.userId, this.totpSecret, this.otpauthUri);
}

class AuthClient {
  final String baseUrl;
  final DeviceStore devices;
  final http.Client _client;
  AuthClient(this.baseUrl, this.devices, {http.Client? client})
      : _client = client ?? http.Client();

  Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body,
      {String? token}) async {
    final res = await _client.post(
      Uri.parse('$baseUrl$path'),
      headers: {
        'content-type': 'application/json',
        if (token != null) 'authorization': 'Bearer $token',
      },
      body: jsonEncode(body),
    );
    final data = res.body.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(res.body) as Map<String, dynamic>;
    data['_status'] = res.statusCode;
    return data;
  }

  /// Create an account. The server receives a DERIVED verifier, never the
  /// password. Returns the TOTP secret for the authenticator app.
  Future<RegistrationStart> register(String email, String password) async {
    final salt = base64.encode(
        List<int>.generate(16, (_) => Random.secure().nextInt(256)));
    const params = KdfParams.defaults;
    final key = await deriveMasterKey(password, salt, params);
    final verifier = await deriveAuthVerifier(key, password);
    zeroKey(key);
    final r = await _post('/auth/register', {
      'email': email,
      'authVerifier': verifier,
      'kdfSalt': salt,
      'kdfMemoryKiB': params.memoryKiB,
      'kdfIterations': params.iterations,
      'kdfParallel': params.parallelism,
    });
    if (r['_status'] != 201) {
      throw AuthException((r['error'] ?? 'registration failed') as String);
    }
    final mfa = r['mfa'] as Map<String, dynamic>;
    return RegistrationStart(
      r['userId'] as String,
      mfa['secret'] as String,
      mfa['otpauthUri'] as String,
    );
  }

  Future<bool> confirmTotp(String userId, String code) async {
    final r = await _post('/auth/mfa/confirm', {'userId': userId, 'code': code});
    return r['_status'] == 200;
  }

  /// Full sign-in: password + TOTP → [Session] holding the vault key.
  Future<Session> login(String email, String password, String code) async {
    final kdfInfo = await _post('/auth/kdf', {'email': email});
    final salt = kdfInfo['kdfSalt'] as String;
    final params = KdfParams(
      memoryKiB: kdfInfo['kdfMemoryKiB'] as int,
      iterations: kdfInfo['kdfIterations'] as int,
      parallelism: kdfInfo['kdfParallel'] as int,
    );
    final key = await deriveMasterKey(password, salt, params);
    final verifier = await deriveAuthVerifier(key, password);

    var identity = await devices.load(email);
    var login = await _post('/auth/login', {
      'email': email,
      'authVerifier': verifier,
      if (identity != null) 'deviceId': identity.deviceId,
    });
    if (login['_status'] == 200 && login['needsDevice'] == true) {
      // Fresh phone: generate REAL device keys and enroll. The signing key
      // is what lets this device later approve — or, via QR pairing, prove
      // its own identity while pending — a real Ed25519/X25519 keypair, not
      // a placeholder, since the server verifies approval signatures against
      // whatever public key was registered here.
      const name = 'Mobile';
      final exchange = await devicekeys.generateExchangeKeys();
      final signing = await devicekeys.generateSigningKeys();
      final dev = await _post('/devices/enroll', {
        'userId': login['userId'],
        'name': name,
        'platform': 'mobile',
        'publicKey': exchange.publicKey,
        'signingPublicKey': signing.publicKey,
      });
      final deviceId = (dev['device'] as Map<String, dynamic>)['id'] as String;
      identity = DeviceIdentity(
        deviceId: deviceId,
        name: name,
        signingPublicKey: signing.publicKey,
        signingPrivateKey: signing.privateKey,
        exchangePublicKey: exchange.publicKey,
        exchangePrivateKey: exchange.privateKey,
      );
      await devices.save(email, identity);
      login = await _post('/auth/login', {
        'email': email,
        'authVerifier': verifier,
        'deviceId': deviceId,
      });
    }
    if (login['_status'] != 200 || login['token'] == null) {
      zeroKey(key);
      throw AuthException((login['error'] ?? 'invalid credentials') as String);
    }

    final mfa = await _post('/auth/mfa', {'token': login['token'], 'code': code});
    if (mfa['_status'] != 200 || mfa['token'] == null) {
      zeroKey(key);
      throw AuthException((mfa['error'] ?? 'invalid MFA code') as String);
    }

    return Session(
      token: mfa['token'] as String,
      userId: login['userId'] as String,
      email: email,
      saltB64: salt,
      kdf: params,
      key: key,
      device: identity!,
    );
  }
}
