/**
 * Attachment envelope: round trip, authenticity, key/context binding, streaming.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import {
  seal,
  open,
  createSealStream,
  createOpenStream,
  sealedSize,
  hexEqual,
  DecryptionError,
  FORMAT_VERSION,
} from '../src/shared/crypto.js';
import { TEST_MASTER_KEY } from './helpers.js';

const KEY = 'attachments/2026/07/msg-1/att-1.enc';

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream as AsyncIterable<Buffer>) chunks.push(c);
  return Buffer.concat(chunks);
}

test('seal/open round trip preserves bytes exactly', () => {
  for (const size of [0, 1, 15, 16, 17, 4096, 100_000]) {
    const plain = randomBytes(size);
    const sealed = seal(plain, TEST_MASTER_KEY, KEY);
    assert.equal(sealed.length, sealedSize(size), `sealedSize wrong for ${size}`);
    assert.deepEqual(open(sealed, TEST_MASTER_KEY, KEY), plain, `round trip failed for ${size}`);
  }
});

test('envelope carries the IMS1 magic and version', () => {
  const sealed = seal(Buffer.from('hello'), TEST_MASTER_KEY, KEY);
  assert.equal(sealed.subarray(0, 4).toString('latin1'), 'IMS1');
  assert.equal(sealed.readUInt8(4), FORMAT_VERSION);
});

test('ciphertext does not contain the plaintext', () => {
  const plain = Buffer.from('the launch code is hunter2, do not share'.repeat(50));
  const sealed = seal(plain, TEST_MASTER_KEY, KEY);
  assert.ok(!sealed.includes(Buffer.from('launch code')), 'plaintext leaked into ciphertext');
});

test('each seal uses a fresh salt and nonce', () => {
  const plain = Buffer.from('same input every time');
  const a = seal(plain, TEST_MASTER_KEY, KEY);
  const b = seal(plain, TEST_MASTER_KEY, KEY);
  assert.notDeepEqual(a, b, 'identical ciphertexts — nonce reuse');
  assert.notDeepEqual(a.subarray(5, 21), b.subarray(5, 21), 'salt repeated');
});

test('tampered ciphertext is rejected', () => {
  const sealed = seal(randomBytes(2048), TEST_MASTER_KEY, KEY);
  for (const pos of [40, Math.floor(sealed.length / 2), sealed.length - 1]) {
    const bad = Buffer.from(sealed);
    bad.writeUInt8(bad.readUInt8(pos) ^ 0x01, pos);
    assert.throws(() => open(bad, TEST_MASTER_KEY, KEY), DecryptionError, `tamper at ${pos} not detected`);
  }
});

test('truncated ciphertext is rejected', () => {
  const sealed = seal(randomBytes(1024), TEST_MASTER_KEY, KEY);
  assert.throws(() => open(sealed.subarray(0, sealed.length - 4), TEST_MASTER_KEY, KEY), DecryptionError);
  assert.throws(() => open(sealed.subarray(0, 10), TEST_MASTER_KEY, KEY), DecryptionError);
});

test('wrong master key cannot decrypt', () => {
  const sealed = seal(Buffer.from('secret'), TEST_MASTER_KEY, KEY);
  assert.throws(() => open(sealed, randomBytes(32), KEY), DecryptionError);
});

test('ciphertext is bound to its object key', () => {
  const sealed = seal(Buffer.from('secret'), TEST_MASTER_KEY, KEY);
  assert.throws(() => open(sealed, TEST_MASTER_KEY, 'attachments/2026/07/msg-1/other.enc'), DecryptionError);
});

test('streaming seal matches buffered open', async () => {
  const plain = randomBytes(300_000);
  const sealed = await collect(Readable.from(plain).pipe(createSealStream(TEST_MASTER_KEY, KEY)));
  assert.equal(sealed.length, sealedSize(plain.length));
  assert.deepEqual(open(sealed, TEST_MASTER_KEY, KEY), plain);
});

test('streaming open matches buffered seal, across chunk boundaries', async () => {
  const plain = randomBytes(70_000);
  const sealed = seal(plain, TEST_MASTER_KEY, KEY);
  // Feed in awkward small chunks so the tag straddles boundaries.
  async function* chunked(): AsyncGenerator<Buffer> {
    for (let i = 0; i < sealed.length; i += 7) yield sealed.subarray(i, i + 7);
  }
  const out = await collect(Readable.from(chunked()).pipe(createOpenStream(TEST_MASTER_KEY, KEY)));
  assert.deepEqual(out, plain);
});

test('streaming open errors on a tampered stream', async () => {
  const plain = randomBytes(50_000);
  const sealed = seal(plain, TEST_MASTER_KEY, KEY);
  const bad = Buffer.from(sealed);
  bad.writeUInt8(bad.readUInt8(1000) ^ 0xff, 1000);
  await assert.rejects(
    pipeline(Readable.from(bad), createOpenStream(TEST_MASTER_KEY, KEY), async function (src) {
      for await (const _ of src) {
        /* drain */
      }
    }),
  );
});

test('hexEqual compares digests safely', () => {
  assert.ok(hexEqual('ab'.repeat(32), 'ab'.repeat(32)));
  assert.ok(!hexEqual('ab'.repeat(32), 'ac'.repeat(32)));
  assert.ok(!hexEqual('abcd', 'abcdef'));
  assert.ok(!hexEqual('zz', 'zz'));
});
