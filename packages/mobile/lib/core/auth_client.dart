import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

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
  Session({
    required this.token,
    required this.userId,
    required this.email,
    required this.saltB64,
    required this.kdf,
    required this.key,
  });
}

class AuthException implements Exception {
  final String message;
  AuthException(this.message);
  @override
  String toString() => message;
}

/// Persists this phone's non-secret device handle per email.
abstract class DeviceStore {
  Future<String?> load(String email);
  Future<void> save(String email, String deviceId);
}

class MemoryDeviceStore implements DeviceStore {
  final Map<String, String> _m = {};
  @override
  Future<String?> load(String email) async => _m[email.toLowerCase()];
  @override
  Future<void> save(String email, String deviceId) async =>
      _m[email.toLowerCase()] = deviceId;
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

    var deviceId = await devices.load(email);
    var login = await _post('/auth/login', {
      'email': email,
      'authVerifier': verifier,
      if (deviceId != null) 'deviceId': deviceId,
    });
    if (login['_status'] == 200 && login['needsDevice'] == true) {
      // Fresh phone: enroll as a device, then log in properly. Placeholder
      // keys, like web/extension — this device authenticates password+TOTP.
      String rand() => base64
          .encode(List<int>.generate(32, (_) => Random.secure().nextInt(256)));
      final dev = await _post('/devices/enroll', {
        'userId': login['userId'],
        'name': 'Mobile',
        'platform': 'mobile',
        'publicKey': rand(),
        'signingPublicKey': rand(),
      });
      deviceId = (dev['device'] as Map<String, dynamic>)['id'] as String;
      await devices.save(email, deviceId);
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
    );
  }
}
