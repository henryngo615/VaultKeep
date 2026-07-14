/**
 * Minimal CBOR (RFC 8949) codec — just the subset WebAuthn needs:
 * unsigned/negative integers, byte strings, text strings, arrays, and maps
 * (with integer or text keys). attestationObject and COSE keys use nothing
 * else. Dependency-free on purpose, like the rest of the server.
 */

export type CborValue =
  | number
  | string
  | Uint8Array
  | CborValue[]
  | Map<number | string, CborValue>;

export function decodeCbor(buf: Uint8Array): CborValue {
  const [value, rest] = decodeItem(buf, 0);
  if (rest !== buf.length) throw new Error("cbor: trailing bytes");
  return value;
}

/** Decode the first CBOR item, returning it plus how many bytes it consumed. */
export function decodeCborFirst(buf: Uint8Array): [CborValue, number] {
  return decodeItem(buf, 0);
}

function decodeItem(buf: Uint8Array, at: number): [CborValue, number] {
  if (at >= buf.length) throw new Error("cbor: truncated");
  const initial = buf[at];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let [len, offset] = readLength(buf, at + 1, info);

  switch (major) {
    case 0: // unsigned int
      return [len, offset];
    case 1: // negative int
      return [-1 - len, offset];
    case 2: {
      // byte string
      const end = offset + len;
      if (end > buf.length) throw new Error("cbor: truncated bytes");
      return [buf.slice(offset, end), end];
    }
    case 3: {
      // text string
      const end = offset + len;
      if (end > buf.length) throw new Error("cbor: truncated text");
      return [new TextDecoder().decode(buf.slice(offset, end)), end];
    }
    case 4: {
      // array
      const arr: CborValue[] = [];
      let cur = offset;
      for (let i = 0; i < len; i++) {
        const [v, next] = decodeItem(buf, cur);
        arr.push(v);
        cur = next;
      }
      return [arr, cur];
    }
    case 5: {
      // map
      const map = new Map<number | string, CborValue>();
      let cur = offset;
      for (let i = 0; i < len; i++) {
        const [k, afterKey] = decodeItem(buf, cur);
        if (typeof k !== "number" && typeof k !== "string") {
          throw new Error("cbor: unsupported map key type");
        }
        const [v, afterVal] = decodeItem(buf, afterKey);
        map.set(k, v);
        cur = afterVal;
      }
      return [map, cur];
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

function readLength(buf: Uint8Array, at: number, info: number): [number, number] {
  if (info < 24) return [info, at];
  if (info === 24) return [buf[at], at + 1];
  if (info === 25) return [(buf[at] << 8) | buf[at + 1], at + 2];
  if (info === 26) {
    return [
      buf[at] * 0x1000000 + ((buf[at + 1] << 16) | (buf[at + 2] << 8) | buf[at + 3]),
      at + 4,
    ];
  }
  throw new Error("cbor: unsupported length encoding");
}

/** Encode the same subset. Used by tests to fabricate authenticator payloads. */
export function encodeCbor(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeItem(value, out);
  return Uint8Array.from(out);
}

function encodeItem(value: CborValue, out: number[]) {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("cbor: only integers supported");
    if (value >= 0) writeHead(0, value, out);
    else writeHead(1, -1 - value, out);
  } else if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    writeHead(3, bytes.length, out);
    for (const b of bytes) out.push(b);
  } else if (value instanceof Uint8Array) {
    writeHead(2, value.length, out);
    for (const b of value) out.push(b);
  } else if (Array.isArray(value)) {
    writeHead(4, value.length, out);
    for (const v of value) encodeItem(v, out);
  } else if (value instanceof Map) {
    writeHead(5, value.size, out);
    for (const [k, v] of value) {
      encodeItem(k, out);
      encodeItem(v, out);
    }
  } else {
    throw new Error("cbor: unsupported value");
  }
}

function writeHead(major: number, len: number, out: number[]) {
  const m = major << 5;
  if (len < 24) out.push(m | len);
  else if (len < 0x100) out.push(m | 24, len);
  else if (len < 0x10000) out.push(m | 25, len >> 8, len & 0xff);
  else out.push(m | 26, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
}
