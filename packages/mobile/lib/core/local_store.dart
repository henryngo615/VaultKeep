import 'dart:io';

/// The on-disk vault is a SINGLE opaque blob — same model as the desktop app.
/// `VaultApp` encrypts its whole state before it reaches the store, so the
/// store needs no key and never sees structure.
abstract class LocalStore {
  Future<String?> readRaw();
  Future<void> writeRaw(String blob);
}

/// In-memory store for tests and previews.
class MemoryStore implements LocalStore {
  String? _blob;
  @override
  Future<String?> readRaw() async => _blob;
  @override
  Future<void> writeRaw(String blob) async => _blob = blob;
}

/// File-backed store. Pure I/O — no crypto, no key.
class FileStore implements LocalStore {
  final String path;
  FileStore(this.path);

  @override
  Future<String?> readRaw() async {
    try {
      final raw = await File(path).readAsString();
      return raw.isEmpty ? null : raw;
    } catch (_) {
      return null; // first run / missing file
    }
  }

  @override
  Future<void> writeRaw(String blob) async {
    final f = File(path);
    await f.parent.create(recursive: true);
    await f.writeAsString(blob, flush: true);
  }
}
