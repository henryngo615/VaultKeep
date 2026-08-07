import 'dart:convert';

import 'auth_client.dart';
import 'local_store.dart';

/// Device identities persisted as a tiny JSON file, keyed by account email.
/// Deliberately unencrypted — this includes each account's signing/exchange
/// PRIVATE keys, but there's no master key available before sign-in to
/// protect it with, the same tradeoff desktop's on-disk `device.json` makes.
/// Shared by the sign-in and recovery screens so both enroll/reuse the same
/// on-disk device identity per account.
class FileDeviceStore implements DeviceStore {
  final LocalStore store;
  FileDeviceStore(this.store);

  Future<Map<String, dynamic>> _read() async {
    final raw = await store.readRaw();
    if (raw == null) return {};
    try {
      return Map<String, dynamic>.from(jsonDecode(raw) as Map);
    } catch (_) {
      return {};
    }
  }

  @override
  Future<DeviceIdentity?> load(String email) async {
    final j = (await _read())[email.toLowerCase()];
    if (j == null) return null;
    return DeviceIdentity.fromJson(Map<String, dynamic>.from(j as Map));
  }

  @override
  Future<void> save(String email, DeviceIdentity identity) async {
    final m = await _read();
    m[email.toLowerCase()] = identity.toJson();
    await store.writeRaw(jsonEncode(m));
  }
}
