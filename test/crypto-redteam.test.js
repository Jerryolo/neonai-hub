import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicKey, createPrivateKey, generateKeyPairSync, sign, webcrypto } from 'node:crypto';
import { canonicalize, blockPayload, createSignedBlock, createSignedBlockAsync, hashBlock, hashBlockAsync, signBlock, signBlockAsync, verifyBlockSignature, verifyBlockSignatureAsync, verifyChain, verifyChainAsync } from '../src/chain.js';

const trusted = generateKeyPairSync('ed25519');
const attacker = generateKeyPairSync('ed25519');
const genesisInput = () => ({ index: 0, previousHash: null, data: { message: 'approved', amount: 10 } });
function chainWith(keys = trusted) {
  const first = createSignedBlock(genesisInput(), keys.privateKey);
  return [first, createSignedBlock({ index: 1, previousHash: first.hash, data: { message: 'next' } }, keys.privateKey)];
}

// The public/private keys and deterministic signature are RFC 8032 section 7.1,
// test 1. The API signs canonical JSON (never the empty message), so use the
// RFC seed to cross-check its bytes against the primitive, then cross-runtime.
const rfcSeed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const rfcPublic = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const rfcPrivateKey = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + rfcSeed, 'hex'), format: 'der', type: 'pkcs8' });
const rfcPublicKey = createPublicKey({ key: Buffer.from('302a300506032b6570032100' + rfcPublic, 'hex'), format: 'der', type: 'spki' });

test('RFC 8032 known-answer primitive and independently specified canonical payload', () => {
  assert.equal(sign(null, Buffer.alloc(0), rfcPrivateKey).toString('hex'), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  const input = { previousHash: null, data: { z: 'ą😀', a: 0 }, index: 0 };
  const expected = '{"data":{"a":0,"z":"ą😀"},"index":0,"previousHash":null}';
  assert.equal(blockPayload(input), expected);
  const signed = createSignedBlock(input, rfcPrivateKey);
  assert.equal(signed.signature, sign(null, Buffer.from(expected), rfcPrivateKey).toString('base64'));
  assert.equal(verifyChain([signed], rfcPublicKey), true);
});

test('no trust, embedded attacker key, substituted trusted key all fail closed', async () => {
  const evil = createSignedBlock({ ...genesisInput(), publicKey: attacker.publicKey.export({ format: 'pem', type: 'spki' }) }, attacker.privateKey);
  for (const key of [undefined, null, trusted.publicKey]) {
    assert.throws(() => verifyChain([evil], key));
    await assert.rejects(verifyChainAsync([evil], key));
  }
});

test('algorithm confusion and private-key-as-verifier rejected', () => {
  const input = genesisInput();
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const valid = createSignedBlock(input, trusted.privateKey);
  const evil = { ...input, hash: hashBlock(input), signature: sign(null, Buffer.from(blockPayload(input)), { key: ec.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64') };
  for (const key of [ec.publicKey, { key: ec.publicKey, dsaEncoding: 'ieee-p1363' }, rsa.publicKey, trusted.privateKey, trusted.privateKey.export({ format: 'pem', type: 'pkcs8' })]) {
    assert.equal(verifyBlockSignature(evil, key).ok, false);
    assert.equal(verifyBlockSignature(valid, key).ok, false);
  }
  for (const key of [ec.privateKey, rsa.privateKey, trusted.publicKey, { key: trusted.privateKey }]) assert.throws(() => signBlock(input, key));
});

test('empty chains rejected by both backends', async () => {
  assert.throws(() => verifyChain([], trusted.publicKey), /EMPTY_CHAIN/);
  await assert.rejects(verifyChainAsync([], trusted.publicKey), /EMPTY_CHAIN/);
});

test('trusted checkpoints reject truncation, substitution and foreign genesis', async () => {
  const chain = chainWith();
  const checkpoint = { expectedLength: 2, expectedTipHash: chain[1].hash, expectedGenesisHash: chain[0].hash };
  assert.equal(verifyChain(chain, trusted.publicKey, checkpoint), true);
  assert.throws(() => verifyChain(chain.slice(0, 1), trusted.publicKey, checkpoint), /checkpoint/);
  assert.throws(() => verifyChain(chain.slice(0, 1), trusted.publicKey, { expectedTipHash: chain[1].hash }), /tip/);
  const foreign = createSignedBlock({ ...genesisInput(), data: 'foreign' }, trusted.privateKey);
  assert.throws(() => verifyChain([foreign], trusted.publicKey, { expectedGenesisHash: chain[0].hash }), /genesis/);
  await assert.rejects(verifyChainAsync([foreign], trusted.publicKey, { expectedGenesisHash: chain[0].hash }), /genesis/);
  // Explicitly record the narrower unanchored guarantee: a valid prefix is valid.
  assert.equal(verifyChain(chain.slice(0, 1), trusted.publicKey), true);
});

test('signature, stored hash, signed previous link and signed index fail independently', () => {
  const chain = chainWith();
  const mutation = structuredClone(chain); mutation[1].data.message = 'attacker'; mutation[1].hash = hashBlock(mutation[1]);
  assert.throws(() => verifyChain(mutation, trusted.publicKey), /signature mismatch/);
  const badHash = structuredClone(chain); badHash[1].hash = '0'.repeat(64);
  assert.equal(verifyBlockSignature(badHash[1], trusted.publicKey).ok, true);
  assert.throws(() => verifyChain(badHash, trusted.publicKey), /hash mismatch/);
  const badLink = [chain[0], createSignedBlock({ ...chain[1], previousHash: '0'.repeat(64) }, trusted.privateKey)];
  assert.equal(verifyBlockSignature(badLink[1], trusted.publicKey).ok, true);
  assert.throws(() => verifyChain(badLink, trusted.publicKey), /previousHash mismatch/);
  const badIndex = [chain[0], createSignedBlock({ ...chain[1], index: 99 }, trusted.privateKey)];
  assert.throws(() => verifyChain(badIndex, trusted.publicKey), /index mismatch/);
});

const cycle = {}; cycle.self = cycle;
const hidden = Object.defineProperty({}, 'hidden', { value: 1 });
const extended = []; extended.extra = 1;
for (const [name, value] of [ ['date', new Date()], ['map', new Map()], ['sparse', Array(1)], ['extended-array', extended], ['cycle', cycle], ['NaN', NaN], ['Infinity', Infinity], ['undefined', undefined], ['bigint', 1n], ['symbol', Symbol('x')], ['hidden', hidden], ['lone-high-surrogate', '\ud800'], ['lone-low-surrogate', '\udfff'], ['symbol-key', { [Symbol('x')]: 1 }] ]) {
  test(`rejects non-JSON ambiguity: ${name}`, () => {
    assert.throws(() => canonicalize(value));
    assert.throws(() => createSignedBlock({ ...genesisInput(), data: value }, trusted.privateKey));
  });
}

test('getter rejected without execution; JSON key order invariant', () => {
  let reads = 0;
  const value = { get data() { reads++; return 'bad'; } };
  assert.throws(() => canonicalize(value)); assert.equal(reads, 0);
  assert.equal(canonicalize({ b: 1, a: { z: 2, y: 3 } }), canonicalize({ a: { y: 3, z: 2 }, b: 1 }));
  assert.notEqual(canonicalize('é'), canonicalize('e\u0301'));
});

test('malformed and noncanonical Base64 rejected, including equivalent pad bits', async () => {
  const valid = chainWith()[0];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const changedPad = valid.signature.slice(0, 85) + alphabet[alphabet.indexOf(valid.signature[85]) + 1] + '==';
  assert.deepEqual(Buffer.from(changedPad, 'base64'), Buffer.from(valid.signature, 'base64'));
  for (const signature of [changedPad, valid.signature + '\n', valid.signature.slice(0, -2), '', 'AA==', 'A'.repeat(88), null]) {
    const bad = { ...valid, signature };
    assert.equal(verifyBlockSignature(bad, trusted.publicKey).ok, false);
    assert.equal((await verifyBlockSignatureAsync(bad, trusted.publicKey)).ok, false);
  }
});

test('Node and WebCrypto interoperate in both directions with imported RFC keys', async () => {
  const privateKey = await webcrypto.subtle.importKey('pkcs8', rfcPrivateKey.export({ format: 'der', type: 'pkcs8' }), 'Ed25519', false, ['sign']);
  const publicKey = await webcrypto.subtle.importKey('raw', Buffer.from(rfcPublic, 'hex'), 'Ed25519', false, ['verify']);
  const input = genesisInput();
  const native = createSignedBlock(input, rfcPrivateKey);
  const browser = await createSignedBlockAsync(input, privateKey);
  assert.deepEqual(native, browser);
  assert.equal(hashBlock(input), await hashBlockAsync(input));
  assert.equal(verifyChain([browser], rfcPublicKey), true);
  assert.equal(await verifyChainAsync([native], publicKey), true);
  assert.throws(() => verifyChain([browser], publicKey), /Async APIs/);
  assert.throws(() => signBlock(input, privateKey), /Async APIs/);
  assert.equal(await signBlockAsync(input, rfcPrivateKey), native.signature);
  assert.equal((await verifyBlockSignatureAsync(native, privateKey)).ok, false);
  const ec = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  assert.equal((await verifyBlockSignatureAsync(native, ec.publicKey)).ok, false);
  await assert.rejects(signBlockAsync(input, ec.privateKey));
});

test('async verification snapshots chain and checkpoints; resolver receives frozen data', async () => {
  const chain = chainWith();
  const options = { expectedTipHash: chain[1].hash };
  const result = verifyChainAsync(chain, (block) => {
    assert.equal(Object.isFrozen(block), true);
    assert.equal(Object.isFrozen(block.data), true);
    assert.throws(() => { block.data.message = 'changed'; }, TypeError);
    return trusted.publicKey;
  }, options);
  chain[1].data.message = 'changed-after-start'; options.expectedTipHash = '0'.repeat(64);
  assert.equal(await result, true);
  await assert.rejects(verifyChainAsync(chain, trusted.publicKey));
  assert.throws(() => verifyChain(chainWith(), async () => trusted.publicKey), /synchronously/);
});

test('async signing snapshots caller payload before yielding', async () => {
  const input = genesisInput();
  const expected = createSignedBlock(input, trusted.privateKey);
  const pending = createSignedBlockAsync(input, trusted.privateKey);
  input.data.amount = 999;
  assert.deepEqual(await pending, expected);
});

test('identity and low-order key forgeries rejected by native and WebCrypto', async () => {
  for (const raw of ['01' + '00'.repeat(31), '00'.repeat(32), 'ec' + 'ff'.repeat(30) + '7f']) {
    const key = createPublicKey({ key: Buffer.from('302a300506032b6570032100' + raw, 'hex'), format: 'der', type: 'spki' });
    const browserKey = await webcrypto.subtle.importKey('raw', Buffer.from(raw, 'hex'), 'Ed25519', false, ['verify']);
    for (const r of ['01' + '00'.repeat(31), '00'.repeat(32)]) {
      const forged = { ...genesisInput(), signature: Buffer.from(r + '00'.repeat(32), 'hex').toString('base64') };
      forged.hash = hashBlock(forged);
      assert.equal(verifyBlockSignature(forged, key).ok, false);
      assert.equal((await verifyBlockSignatureAsync(forged, browserKey)).ok, false);
    }
  }
});

test('Ed25519 rejects noncanonical S scalar instead of reducing modulo group order', async () => {
  const valid = chainWith()[0];
  const bytes = Buffer.from(valid.signature, 'base64');
  let scalar = 0n;
  for (let i = 63; i >= 32; i--) scalar = (scalar << 8n) | BigInt(bytes[i]);
  scalar += (1n << 252n) + 27742317777372353535851937790883648493n;
  for (let i = 32; i < 64; i++) { bytes[i] = Number(scalar & 255n); scalar >>= 8n; }
  const forged = { ...valid, signature: bytes.toString('base64') };
  assert.equal(verifyBlockSignature(forged, trusted.publicKey).ok, false);
  const publicKey = await webcrypto.subtle.importKey('spki', trusted.publicKey.export({ type: 'spki', format: 'der' }), 'Ed25519', false, ['verify']);
  assert.equal((await verifyBlockSignatureAsync(forged, publicKey)).ok, false);
});

test('chain container accessors and sparse arrays rejected without invoking getter', () => {
  let reads = 0;
  const accessor = [];
  Object.defineProperty(accessor, '0', { enumerable: true, get() { reads++; return chainWith()[0]; } });
  assert.throws(() => verifyChain(accessor, trusted.publicKey));
  assert.equal(reads, 0);
  assert.throws(() => verifyChain(Array(2), trusted.publicKey));
  const extended = chainWith(); extended.extra = 'hidden path';
  assert.throws(() => verifyChain(extended, trusted.publicKey));
});

test('oversized, excessive-depth and oversized-chain inputs reject boundedly', () => {
  assert.throws(() => canonicalize('😀'.repeat(70000)), /size limit/);
  let deep = null; for (let i = 0; i < 100; i++) deep = [deep];
  assert.throws(() => canonicalize(deep), /complexity limit/);
  assert.throws(() => verifyChain(Array(1001).fill(chainWith()[0]), trusted.publicKey), /block limit/);
});
