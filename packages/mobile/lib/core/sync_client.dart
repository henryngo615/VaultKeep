import 'dart:convert';

import 'package:http/http.dart' as http;

/// Client-side view of the sync server — the same Transport contract the
/// desktop core uses, so the mobile app talks to the identical API.
class RemoteItem {
  final String id;
  final String ciphertext;
  final int version;
  final String updatedAt;
  RemoteItem({
    required this.id,
    required this.ciphertext,
    required this.version,
    required this.updatedAt,
  });
  factory RemoteItem.fromJson(Map<String, dynamic> j) => RemoteItem(
        id: j['id'] as String,
        ciphertext: j['ciphertext'] as String,
        version: j['version'] as int,
        updatedAt: (j['updatedAt'] ?? '') as String,
      );
}

class PushOutcome {
  final String status; // "ok" | "conflict"
  final int? version;
  final RemoteItem? server;
  PushOutcome({required this.status, this.version, this.server});
  bool get ok => status == 'ok';
  factory PushOutcome.fromJson(Map<String, dynamic> j) => PushOutcome(
        status: j['status'] as String,
        version: j['version'] as int?,
        server: j['server'] == null
            ? null
            : RemoteItem.fromJson(j['server'] as Map<String, dynamic>),
      );
}

abstract class Transport {
  Future<List<RemoteItem>> pull({String? since});
  Future<PushOutcome> push(String id, String ciphertext, int? baseVersion);
}

/// HTTP transport for production (Bearer token auth).
class HttpTransport implements Transport {
  final String baseUrl;
  final String token;
  final http.Client _client;
  HttpTransport(this.baseUrl, this.token, {http.Client? client})
      : _client = client ?? http.Client();

  Map<String, String> get _headers => {
        'authorization': 'Bearer $token',
        'content-type': 'application/json',
      };

  @override
  Future<List<RemoteItem>> pull({String? since}) async {
    final uri = Uri.parse('$baseUrl/vault/items')
        .replace(queryParameters: since != null ? {'since': since} : null);
    final res = await _client.get(uri, headers: _headers);
    if (res.statusCode != 200) {
      throw Exception('pull failed: ${res.statusCode}');
    }
    final items = (jsonDecode(res.body)['items'] as List<dynamic>);
    return items
        .map((e) => RemoteItem.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  @override
  Future<PushOutcome> push(String id, String ciphertext, int? baseVersion) async {
    final res = await _client.put(
      Uri.parse('$baseUrl/vault/items/$id'),
      headers: _headers,
      body: jsonEncode({'ciphertext': ciphertext, 'baseVersion': baseVersion}),
    );
    return PushOutcome.fromJson(jsonDecode(res.body) as Map<String, dynamic>);
  }
}
