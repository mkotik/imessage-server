/**
 * Client-side authenticated encryption for attachment blobs and database backups.
 *
 * iDrive E2 never receives plaintext. Every object is sealed on this VPS before
 * upload and only ever opened here.
 *
 * Envelope format (version 1) — all multi-byte fields big-endian:
 *
 *   offset  size  field
 *   0       4     magic "IMS1"
 *   4       1     format version (0x01)
 *   5       1     KDF id (0x01 = HKDF-SHA256)
 *   6       1     cipher id (0x01 = AES-256-GCM)
 *   7       1     reserved (0x00)
 *   8       16    salt        — random per object, input to the KDF
 *   24      12    nonce       — random per object
 *   36      N     ciphertext  — same length as the plaintext (GCM is a stream cipher)
 *   36+N    16    auth tag
 *
 * The 36-byte header is fed to GCM as additional authenticated data, so a
 * tampered salt, nonce or version fails the tag check instead of silently
 * decrypting to garbage.
 *
 * Keys are never reused across objects: the object key is
 * HKDF-SHA256(masterKey, salt, info = "imsg-attachment-v1|" + objectKey). Because
 * the salt is fresh per object, a fixed nonce would still be safe; a random one
 * is used anyway as defence in depth.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, timingSafeEqual, type CipherGCM, type DecipherGCM } from 'node:crypto';
import { Transform, type TransformCallback } from 'node:stream';

export const MAGIC = Buffer.from('IMS1', 'ascii');
export const FORMAT_VERSION = 1;
const KDF_HKDF_SHA256 = 1;
const CIPHER_AES_256_GCM = 1;

export const SALT_LEN = 16;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const HEADER_LEN = 4 + 1 + 1 + 1 + 1 + SALT_LEN + NONCE_LEN; // 36

export class DecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecryptionError';
  }
}

/** Ciphertext length for a known plaintext length — lets us set Content-Length up front. */
export function sealedSize(plaintextBytes: number): number {
  return HEADER_LEN + plaintextBytes + TAG_LEN;
}

function deriveKey(masterKey: Buffer, salt: Buffer, objectKey: string): Buffer {
  const info = Buffer.from(`imsg-attachment-v1|${objectKey}`, 'utf8');
  return Buffer.from(hkdfSync('sha256', masterKey, salt, info, 32));
}

function buildHeader(salt: Buffer, nonce: Buffer): Buffer {
  const h = Buffer.alloc(HEADER_LEN);
  MAGIC.copy(h, 0);
  h[4] = FORMAT_VERSION;
  h[5] = KDF_HKDF_SHA256;
  h[6] = CIPHER_AES_256_GCM;
  h[7] = 0;
  salt.copy(h, 8);
  nonce.copy(h, 8 + SALT_LEN);
  return h;
}

function parseHeader(h: Buffer): { salt: Buffer; nonce: Buffer } {
  if (h.length < HEADER_LEN) throw new DecryptionError('truncated header');
  if (!h.subarray(0, 4).equals(MAGIC)) throw new DecryptionError('bad magic');
  if (h[4] !== FORMAT_VERSION) throw new DecryptionError(`unsupported format version ${h[4]}`);
  if (h[5] !== KDF_HKDF_SHA256) throw new DecryptionError('unsupported kdf');
  if (h[6] !== CIPHER_AES_256_GCM) throw new DecryptionError('unsupported cipher');
  return { salt: h.subarray(8, 8 + SALT_LEN), nonce: h.subarray(8 + SALT_LEN, HEADER_LEN) };
}

// ---------------------------------------------------------------------------
// Buffer API — used for database backups and small payloads.
// ---------------------------------------------------------------------------

export function seal(plaintext: Buffer, masterKey: Buffer, objectKey: string): Buffer {
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const header = buildHeader(salt, nonce);
  const cipher = createCipheriv('aes-256-gcm', deriveKey(masterKey, salt, objectKey), nonce) as CipherGCM;
  cipher.setAAD(header);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([header, body, cipher.getAuthTag()]);
}

export function open(sealed: Buffer, masterKey: Buffer, objectKey: string): Buffer {
  if (sealed.length < HEADER_LEN + TAG_LEN) throw new DecryptionError('ciphertext too short');
  const header = sealed.subarray(0, HEADER_LEN);
  const { salt, nonce } = parseHeader(header);
  const tag = sealed.subarray(sealed.length - TAG_LEN);
  const body = sealed.subarray(HEADER_LEN, sealed.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', deriveKey(masterKey, salt, objectKey), nonce) as DecipherGCM;
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    // Deliberately opaque: never reveal whether the key or the data was wrong.
    throw new DecryptionError('authentication failed');
  }
}

// ---------------------------------------------------------------------------
// Streaming API — used for attachments, which may be up to 100 MB on a box
// with a 512 MB memory cap. Neither direction ever holds the whole file.
// ---------------------------------------------------------------------------

/** Transform that emits header ‖ ciphertext ‖ tag. */
export function createSealStream(masterKey: Buffer, objectKey: string): Transform {
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const header = buildHeader(salt, nonce);
  const cipher = createCipheriv('aes-256-gcm', deriveKey(masterKey, salt, objectKey), nonce) as CipherGCM;
  cipher.setAAD(header);
  let wroteHeader = false;
  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      try {
        if (!wroteHeader) {
          this.push(header);
          wroteHeader = true;
        }
        this.push(cipher.update(chunk));
        cb();
      } catch (err) {
        cb(err as Error);
      }
    },
    flush(cb: TransformCallback) {
      try {
        if (!wroteHeader) this.push(header);
        this.push(cipher.final());
        this.push(cipher.getAuthTag());
        cb();
      } catch (err) {
        cb(err as Error);
      }
    },
  });
}

/**
 * Transform that consumes header ‖ ciphertext ‖ tag and emits plaintext.
 *
 * GCM cannot authenticate until the tag arrives, so plaintext is emitted before
 * it is verified. The stream errors at the end if the tag does not match, and
 * consumers MUST treat a stream error as "discard everything produced". Callers
 * that cannot honour that (e.g. anything handing bytes to a model) should use
 * `open()` on a fully buffered object instead.
 */
export function createOpenStream(masterKey: Buffer, objectKey: string): Transform {
  let head = Buffer.alloc(0);
  let decipher: DecipherGCM | null = null;
  // Rolling buffer that always retains the last TAG_LEN bytes seen, because the
  // tag is only identifiable once the input ends.
  let tail = Buffer.alloc(0);

  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      try {
        if (!decipher) {
          head = Buffer.concat([head, chunk]);
          if (head.length < HEADER_LEN) return cb();
          const header = head.subarray(0, HEADER_LEN);
          const { salt, nonce } = parseHeader(header);
          decipher = createDecipheriv('aes-256-gcm', deriveKey(masterKey, salt, objectKey), nonce) as DecipherGCM;
          decipher.setAAD(header);
          chunk = head.subarray(HEADER_LEN);
          head = Buffer.alloc(0);
        }
        const buf = Buffer.concat([tail, chunk]);
        if (buf.length <= TAG_LEN) {
          tail = buf;
          return cb();
        }
        const body = buf.subarray(0, buf.length - TAG_LEN);
        tail = buf.subarray(buf.length - TAG_LEN);
        this.push(decipher.update(body));
        cb();
      } catch (err) {
        cb(err instanceof DecryptionError ? err : new DecryptionError('decrypt failed'));
      }
    },
    flush(cb: TransformCallback) {
      try {
        if (!decipher) return cb(new DecryptionError('truncated ciphertext'));
        if (tail.length !== TAG_LEN) return cb(new DecryptionError('missing auth tag'));
        decipher.setAuthTag(tail);
        this.push(decipher.final());
        cb();
      } catch {
        cb(new DecryptionError('authentication failed'));
      }
    },
  });
}

/** Constant-time comparison for hex digests. */
export function hexEqual(a: string, b: string): boolean {
  // Buffer.from(x, 'hex') silently stops at the first non-hex character, so
  // two garbage strings would both decode to empty and compare equal. Validate
  // the encoding before comparing.
  if (a.length !== b.length || a.length === 0) return false;
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== a.length / 2 || bb.length !== b.length / 2) return false;
  return timingSafeEqual(ab, bb);
}
