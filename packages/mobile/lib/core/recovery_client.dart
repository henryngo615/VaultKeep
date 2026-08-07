import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'devicekeys.dart' as devicekeys;
import 'recovery.dart';
import 'vault_crypto.dart';

class RecoveryException implements Exception {
  final String message;
  RecoveryException(this.message);
  @override
  String toString() => message;
}

/// What `/recovery/begin` hands back: enough to unwrap the OLD master key
/// and, separately, to derive a NEW one once the user picks a new password.
class RecoveredMasterKey {
  final Uint8List masterKey;
  final String kdfSaltB64;
  final KdfParams kdf;
  RecoveredMasterKey(this.masterKey, this.kdfSaltB64, this.kdf);
}

class EmergencyContact {
  final String id;
  final String contactEmail;
  final String state; // enrolled | pending | denied | released
  final String? unlockAt;
  EmergencyContact(this.id, this.contactEmail, this.state, this.unlockAt);
}

/// Client for `/recovery/*` and `/emergency/*` — the mobile counterpart of
/// `packages/server/src/recovery/recovery.service.ts`. No server changes:
/// this only calls the contract #5 already shipped.
class RecoveryClient {
  final String baseUrl;
  final http.Client _client;
  RecoveryClient(this.baseUrl, {http.Client? client})
      : _client = client ?? http.Client();

  Future<Map<String, dynamic>> _send(
    String method,
    String path, {
    Map<String, dynamic>? body,
    String? token,
  }) async {
    final headers = {
      'content-type': 'application/json',
      if (token != null) 'authorization': 'Bearer $token',
    };
    final uri = Uri.parse('$baseUrl$path');
    final res = method == 'GET'
        ? await _client.get(uri, headers: headers)
        : await _client.post(uri, headers: headers, body: jsonEncode(body ?? {}));
    final data = res.body.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(res.body) as Map<String, dynamic>;
    data['_status'] = res.statusCode;
    return data;
  }

  // --- owner: set up / rotate the recovery key (authenticated) -------------

  /// Generates a NEW recovery key, wraps [masterKey] under it, and registers
  /// it with the server. Returns the recovery key — show it to the user
  /// exactly once; it isn't recoverable from anything stored server-side.
  Future<String> setup({
    required String token,
    required Uint8List masterKey,
    required String kdfSaltB64,
  }) async {
    final recoveryKey = generateRecoveryKey();
    final parts = await deriveRecoveryParts(recoveryKey, kdfSaltB64);
    final wrapped = await wrapMasterKey(parts.wrapKey, masterKey);
    final r = await _send('POST', '/recovery/setup',
        token: token,
        body: {'authVerifier': parts.authVerifier, 'wrappedKey': wrapped});
    if (r['_status'] != 201) {
      throw RecoveryException((r['error'] ?? 'could not set up recovery') as String);
    }
    return recoveryKey;
  }

  Future<bool> isConfigured(String token) async {
    final r = await _send('GET', '/recovery/status', token: token);
    return r['_status'] == 200 && r['configured'] == true;
  }

  // --- forgotten-password recovery (pre-auth) -------------------------------

  /// Step 1: present the recovery key, get the old master key back. Throws
  /// [RecoveryException] on a wrong recovery key or unknown email.
  Future<RecoveredMasterKey> recoverMasterKey(
      String email, String recoveryKey) async {
    final kdfInfo = await _send('POST', '/auth/kdf', body: {'email': email});
    final saltB64 = kdfInfo['kdfSalt'] as String?;
    if (saltB64 == null) throw RecoveryException('unknown account');
    final kdf = KdfParams(
      memoryKiB: kdfInfo['kdfMemoryKiB'] as int,
      iterations: kdfInfo['kdfIterations'] as int,
      parallelism: kdfInfo['kdfParallel'] as int,
    );

    final parts = await deriveRecoveryParts(recoveryKey, saltB64);
    final begin = await _send('POST', '/recovery/begin',
        body: {'email': email, 'authVerifier': parts.authVerifier});
    if (begin['_status'] != 200 || begin['wrappedKey'] == null) {
      throw RecoveryException((begin['error'] ?? 'invalid recovery key') as String);
    }
    final masterKey =
        await unwrapMasterKey(parts.wrapKey, begin['wrappedKey'] as String);
    return RecoveredMasterKey(masterKey, saltB64, kdf);
  }

  /// Step 2: reset the LOGIN verifier to one derived from a new password.
  /// Does NOT touch vault ciphertext — re-encrypting under the new key is
  /// the caller's job once it has a working session (see `VaultApp.rekey`).
  Future<void> completeWithNewPassword({
    required String email,
    required String recoveryKey,
    required String kdfSaltB64,
    required Uint8List newMasterKey,
    required String newPassword,
  }) async {
    final parts = await deriveRecoveryParts(recoveryKey, kdfSaltB64);
    final newVerifier = await deriveAuthVerifier(newMasterKey, newPassword);
    final r = await _send('POST', '/recovery/complete', body: {
      'email': email,
      'authVerifier': parts.authVerifier,
      'newAuthVerifier': newVerifier,
    });
    if (r['_status'] != 200 || r['ok'] != true) {
      throw RecoveryException((r['error'] ?? 'recovery failed') as String);
    }
  }

  // --- emergency contacts: owner side (authenticated) -----------------------

  /// Seal [masterKey] to the contact's X25519 public key and register them.
  /// [contactSigningPublicKey]/[contactExchangePublicKey] must already be
  /// known (shared out-of-band by the contact from their own device).
  Future<EmergencyContact> addContact({
    required String token,
    required Uint8List masterKey,
    required String contactEmail,
    required String contactSigningPublicKey,
    required String contactExchangePublicKey,
  }) async {
    final sealed = await wrapKeyForContact(masterKey, contactExchangePublicKey);
    final r = await _send('POST', '/emergency/contacts', token: token, body: {
      'contactEmail': contactEmail,
      'contactSigningPublicKey': contactSigningPublicKey,
      'ephemeralPublicKey': sealed.ephemeralPublicKey,
      'wrappedKey': sealed.blob,
    });
    if (r['_status'] != 201) {
      throw RecoveryException((r['error'] ?? 'could not add contact') as String);
    }
    final c = r['contact'] as Map<String, dynamic>;
    return EmergencyContact(c['id'] as String, c['contactEmail'] as String,
        c['state'] as String, null);
  }

  Future<List<EmergencyContact>> listContacts(String token) async {
    final r = await _send('GET', '/emergency/contacts', token: token);
    if (r['_status'] != 200) return const [];
    return (r['contacts'] as List<dynamic>)
        .cast<Map<String, dynamic>>()
        .map((c) => EmergencyContact(c['id'] as String, c['contactEmail'] as String,
            c['state'] as String, c['unlockAt'] as String?))
        .toList();
  }

  /// Permanently cancels a pending request; the contact must be re-enrolled
  /// to try again.
  Future<bool> denyContact(String token, String contactId) async {
    final r = await _send('POST', '/emergency/deny',
        token: token, body: {'contactId': contactId});
    return r['_status'] == 200 && r['ok'] == true;
  }

  // --- emergency contacts: contact side (pre-auth, signature-authenticated) -

  /// The contact starts the waiting period by proving control of their
  /// signing key over `emergency-request:<contactId>`.
  Future<String> requestAccess(String contactId, String signingPrivateKeyB64) async {
    final signature = await devicekeys.signMessage(
        signingPrivateKeyB64, 'emergency-request:$contactId');
    final r = await _send('POST', '/emergency/request',
        body: {'contactId': contactId, 'signature': signature});
    if (r['_status'] != 202 || r['unlockAt'] == null) {
      throw RecoveryException((r['error'] ?? 'request refused') as String);
    }
    return r['unlockAt'] as String;
  }

  /// After the waiting period, the contact collects the sealed key and
  /// unseals it locally with their own exchange private key.
  Future<Uint8List> collect(
    String contactId,
    String signingPrivateKeyB64,
    String exchangePrivateKeyB64,
  ) async {
    final signature = await devicekeys.signMessage(
        signingPrivateKeyB64, 'emergency-collect:$contactId');
    final r = await _send('POST', '/emergency/collect',
        body: {'contactId': contactId, 'signature': signature});
    if (r['_status'] != 200 || r['wrappedKey'] == null) {
      if (r['waitUntil'] != null) {
        throw RecoveryException('waiting period active until ${r['waitUntil']}');
      }
      throw RecoveryException((r['error'] ?? 'collect refused') as String);
    }
    final wrapped = ContactWrappedKey(
        r['ephemeralPublicKey'] as String, r['wrappedKey'] as String);
    return unwrapKeyFromContact(exchangePrivateKeyB64, wrapped);
  }
}
