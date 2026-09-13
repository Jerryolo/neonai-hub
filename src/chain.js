// Browser + Node implementation. Never infer signer trust from the input chain.
const LIMITS = Object.freeze({ depth: 64, nodes: 100000, blockBytes: 262144, chainBytes: 16777216, blocks: 1000 });
const encoder = new TextEncoder();
const HASH = /^[0-9a-f]{64}$/;
const ED25519 = { name: 'Ed25519' };

// Compressed small-order y encodings from libsodium ge25519_has_small_order
// (1.0.18-RELEASE). These are public encoding checks, not curve arithmetic.
// Both sign bits are rejected; y >= p is noncanonical. Native crypto still
// performs the signature equation. See THIRD-PARTY-NOTICES.md.
const SMALL_ORDER_Y = new Set([
  '00'.repeat(32), '01' + '00'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ec' + 'ff'.repeat(30) + '7f',
]);
const FIELD_P = (1n << 255n) - 19n;
const GROUP_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const checkedPublicKeys = new WeakSet();
function littleInteger(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}
function assertPointEncoding(bytes) {
  if (bytes.length !== 32) throw new TypeError('Invalid Ed25519 point length');
  const y = Uint8Array.from(bytes); y[31] &= 0x7f;
  if (littleInteger(y) >= FIELD_P || SMALL_ORDER_Y.has(hex(y))) {
    throw new TypeError('Noncanonical or small-order Ed25519 point');
  }
}
async function checkedWebPublicKey(key) {
  webKey(key, 'public');
  if (!key.extractable) throw new TypeError('Verification requires an exportable public CryptoKey for encoding validation; import public material with extractable=true');
  if (!checkedPublicKeys.has(key)) {
    assertPointEncoding(new Uint8Array(await subtleCrypto().exportKey('raw', key)));
    checkedPublicKeys.add(key);
  }
  return key;
}


function nodeCrypto() {
  const crypto = globalThis.process?.getBuiltinModule?.('node:crypto');
  if (!crypto) throw new Error('Synchronous crypto requires Node >=22.12; use the Async APIs in browsers');
  return crypto;
}

function subtleCrypto() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto unavailable: a secure browser context is required');
  return subtle;
}

function validString(value) {
  if (value.length > LIMITS.blockBytes) throw new RangeError('Payload exceeds size limit');
  // Reject lone surrogates instead of silently encoding U+FFFD / nonportable JSON.
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('Lone Unicode surrogate');
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new TypeError('Lone Unicode surrogate');
  }
  return JSON.stringify(value);
}

// JSON data only: no toJSON hooks, accessors, symbols, hidden properties, classes,
// sparse arrays or cycles. Sorting is UTF-16; Unicode is NOT normalized.
export function canonicalize(value) {
  const ancestors = new Set();
  let nodes = 0;
  let chars = 0;
  function part(text) {
    chars += text.length;
    if (chars > LIMITS.blockBytes) throw new RangeError('Payload exceeds size limit');
    return text;
  }
  function visit(item, depth) {
    if (++nodes > LIMITS.nodes || depth > LIMITS.depth) throw new RangeError('Payload exceeds complexity limit');
    if (item === null || typeof item === 'boolean') return part(JSON.stringify(item));
    if (typeof item === 'string') return part(validString(item));
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new TypeError('Payload contains a non-finite number');
      return part(JSON.stringify(item));
    }
    if (!item || typeof item !== 'object') throw new TypeError(`Payload contains unsupported ${typeof item} value`);
    const array = Array.isArray(item);
    const proto = Object.getPrototypeOf(item);
    if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) {
      throw new TypeError('Payload requires plain JSON objects and arrays');
    }
    if (ancestors.has(item)) throw new TypeError('Payload contains a cycle');
    ancestors.add(item);
    const keys = Reflect.ownKeys(item);
    if (keys.length > LIMITS.nodes) throw new RangeError('Payload exceeds complexity limit');
    if (keys.some(key => typeof key !== 'string')) throw new TypeError('Symbol properties are unsupported');
    const descriptors = Object.getOwnPropertyDescriptors(item);
    for (const key of keys) {
      if (array && key === 'length') continue;
      const desc = descriptors[key];
      if (!desc.enumerable || !Object.hasOwn(desc, 'value')) throw new TypeError('Accessors and hidden properties are unsupported');
    }
    let result;
    if (array) {
      const length = descriptors.length.value;
      if (length > LIMITS.nodes || keys.length !== length + 1) throw new TypeError('Sparse or extended arrays are unsupported');
      const items = [];
      for (let i = 0; i < length; i++) {
        if (!Object.hasOwn(descriptors, String(i))) throw new TypeError('Sparse arrays are unsupported');
        items.push(visit(descriptors[i].value, depth + 1));
      }
      result = part('[') + items.join(part(',')) + part(']');
      chars += Math.max(0, length - 2); // account for repeated separators
    } else {
      const items = keys.sort().map(key => part(validString(key)) + part(':') + visit(descriptors[key].value, depth + 1));
      result = part('{') + items.join(part(',')) + part('}');
      chars += Math.max(0, keys.length - 2);
    }
    ancestors.delete(item);
    if (chars > LIMITS.blockBytes) throw new RangeError('Payload exceeds size limit');
    return result;
  }
  const text = visit(value, 0);
  if (encoder.encode(text).length > LIMITS.blockBytes) throw new RangeError('Payload exceeds UTF-8 size limit');
  return text;
}

function snapshotBlock(block) {
  if (!block || typeof block !== 'object' || Array.isArray(block)) throw new TypeError('Block must be a plain object');
  return JSON.parse(canonicalize(block));
}

function payloadOfSnapshot(block) {
  const { hash, signature, ...payload } = block;
  return canonicalize(payload);
}

export function blockPayload(block) {
  return payloadOfSnapshot(snapshotBlock(block));
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
function base64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let text = '';
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text);
}
function signatureBytes(signature) {
  if (typeof signature !== 'string' || !signature.length) throw new TypeError('missing signature');
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signature)) throw new TypeError('signature is not valid base64');
  const bytes = typeof Buffer !== 'undefined'
    ? new Uint8Array(Buffer.from(signature, 'base64'))
    : Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  if (bytes.length !== 64 || base64(bytes) !== signature) throw new TypeError('signature is not canonical 64-byte base64');
  assertPointEncoding(bytes.subarray(0, 32));
  if (littleInteger(bytes.subarray(32)) >= GROUP_L) throw new TypeError('Noncanonical Ed25519 S scalar');
  return bytes;
}

function isCryptoKey(key) {
  return typeof globalThis.CryptoKey !== 'undefined' && key instanceof globalThis.CryptoKey;
}
function webKey(key, type) {
  if (!isCryptoKey(key) || key.type !== type || key.algorithm.name !== 'Ed25519' || !key.usages.includes(type === 'private' ? 'sign' : 'verify')) {
    throw new TypeError(`A trusted Ed25519 ${type} CryptoKey is required`);
  }
  return key;
}
function nativeKey(key, type) {
  if (!key) throw new TypeError('missing trusted public/private key');
  const crypto = nodeCrypto();
  let normalized;
  if (isCryptoKey(key)) {
    webKey(key, type);
    if (!key.extractable) throw new TypeError('Use Async APIs with non-extractable CryptoKey material');
    normalized = crypto.KeyObject.from(key);
  } else if (key instanceof crypto.KeyObject) {
    normalized = key;
  } else if (typeof key === 'string' || (typeof Buffer !== 'undefined' && Buffer.isBuffer(key))) {
    // Only PEM import; arbitrary crypto option objects cannot change algorithms.
    if (type === 'public' && !String(key).startsWith('-----BEGIN PUBLIC KEY-----')) {
      throw new TypeError('A public PEM key is required');
    }
    normalized = type === 'public' ? crypto.createPublicKey(key) : crypto.createPrivateKey(key);
  } else throw new TypeError('A trusted Ed25519 key object or PEM is required');
  if (normalized.type !== type || normalized.asymmetricKeyType !== 'ed25519') throw new TypeError(`An Ed25519 ${type} key is required`);
  if (type === 'public' && !checkedPublicKeys.has(normalized)) {
    assertPointEncoding(Buffer.from(normalized.export({ format: 'jwk' }).x, 'base64url'));
    checkedPublicKeys.add(normalized);
  }
  return normalized;
}

export function hashBlock(block) {
  return nodeCrypto().createHash('sha256').update(blockPayload(block), 'utf8').digest('hex');
}
export async function hashBlockAsync(block) {
  const bytes = encoder.encode(blockPayload(block));
  return hex(await subtleCrypto().digest('SHA-256', bytes));
}
export function signBlock(block, privateKey) {
  const bytes = encoder.encode(blockPayload(block));
  return base64(nodeCrypto().sign(null, bytes, nativeKey(privateKey, 'private')));
}
export async function signBlockAsync(block, privateKey) {
  const bytes = encoder.encode(blockPayload(block));
  if (!isCryptoKey(privateKey)) return base64(nodeCrypto().sign(null, bytes, nativeKey(privateKey, 'private')));
  return base64(await subtleCrypto().sign(ED25519, webKey(privateKey, 'private'), bytes));
}

export function verifyBlockSignature(block, publicKey) {
  try {
    const copy = snapshotBlock(block);
    const key = nativeKey(publicKey, 'public');
    const ok = nodeCrypto().verify(null, encoder.encode(payloadOfSnapshot(copy)), key, signatureBytes(copy.signature));
    return ok ? { ok: true } : { ok: false, reason: 'Ed25519 signature mismatch' };
  } catch (error) {
    return { ok: false, reason: `invalid Ed25519 signature: ${error.message}` };
  }
}
export async function verifyBlockSignatureAsync(block, publicKey) {
  try {
    const copy = snapshotBlock(block);
    if (!isCryptoKey(publicKey)) return verifyBlockSignature(copy, publicKey);
    const key = await checkedWebPublicKey(publicKey);
    const ok = await subtleCrypto().verify(ED25519, key, signatureBytes(copy.signature), encoder.encode(payloadOfSnapshot(copy)));
    return ok ? { ok: true } : { ok: false, reason: 'Ed25519 signature mismatch' };
  } catch (error) {
    return { ok: false, reason: `invalid Ed25519 signature: ${error.message}` };
  }
}

function freezeDeep(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freezeDeep);
    Object.freeze(value);
  }
  return value;
}
function snapshotChain(chain) {
  if (!Array.isArray(chain) || Object.getPrototypeOf(chain) !== Array.prototype) throw new TypeError('Chain must be an array');
  if (!chain.length) throw new Error('Chain verification failed: EMPTY_CHAIN');
  if (chain.length > LIMITS.blocks) throw new RangeError('Chain exceeds block limit');
  const keys = Reflect.ownKeys(chain);
  if (keys.length !== chain.length + 1) throw new TypeError('Chain must be a dense array');
  let bytes = 0;
  const result = [];
  for (let index = 0; index < chain.length; index++) {
    const desc = Object.getOwnPropertyDescriptor(chain, String(index));
    if (!desc?.enumerable || !Object.hasOwn(desc, 'value')) throw new TypeError('Chain accessors or sparse arrays are unsupported');
    const copy = snapshotBlock(desc.value);
    bytes += encoder.encode(canonicalize(copy)).length;
    if (bytes > LIMITS.chainBytes) throw new RangeError('Chain exceeds byte limit');
    result.push(freezeDeep(copy));
  }
  return Object.freeze(result);
}
function checkpoint(options) {
  const copy = snapshotBlock(options);
  const allowed = ['expectedLength', 'expectedTipHash', 'expectedGenesisHash'];
  if (Object.keys(copy).some(key => !allowed.includes(key))) throw new TypeError('Unknown checkpoint option');
  if (Object.hasOwn(copy, 'expectedLength') && (!Number.isSafeInteger(copy.expectedLength) || copy.expectedLength < 1 || copy.expectedLength > LIMITS.blocks)) throw new TypeError('Invalid expectedLength');
  for (const name of allowed.slice(1)) if (Object.hasOwn(copy, name) && !HASH.test(copy[name])) throw new TypeError(`Invalid ${name}`);
  return copy;
}
function assertCheckpoint(chain, options) {
  if (options.expectedLength !== undefined && chain.length !== options.expectedLength) throw new Error('Chain checkpoint length mismatch');
  if (options.expectedTipHash !== undefined && chain.at(-1).hash !== options.expectedTipHash) throw new Error('Chain checkpoint tip mismatch');
  if (options.expectedGenesisHash !== undefined && chain[0].hash !== options.expectedGenesisHash) throw new Error('Chain checkpoint genesis mismatch');
}
function keyFor(block, index, keyOrResolver) {
  if (!keyOrResolver) throw new Error('Chain verification requires an externally trusted public key');
  const key = typeof keyOrResolver === 'function' ? keyOrResolver(block, index) : keyOrResolver;
  if (!key || typeof key.then === 'function') throw new Error('Trusted key resolver must return a key synchronously');
  return key;
}
function assertIntegrity(chain, block, index, hash, result) {
  if (!result.ok) throw new Error(`Chain verification failed at block ${index}: ${result.reason}`);
  if (block.hash !== hash) throw new Error(`Chain verification failed at block ${index}: SHA-256 hash mismatch`);
  if (block.previousHash !== (index === 0 ? null : chain[index - 1].hash)) throw new Error(`Chain verification failed at block ${index}: previousHash mismatch`);
  if (Object.hasOwn(block, 'index') && (!Number.isSafeInteger(block.index) || block.index !== index)) throw new Error(`Chain verification failed at block ${index}: index mismatch`);
}
export function verifyChain(chain, publicKeyOrResolver, options = {}) {
  const copy = snapshotChain(chain);
  const anchor = checkpoint(options);
  for (const [index, block] of copy.entries()) {
    const result = verifyBlockSignature(block, keyFor(block, index, publicKeyOrResolver));
    assertIntegrity(copy, block, index, hashBlock(block), result);
  }
  assertCheckpoint(copy, anchor);
  return true;
}
export async function verifyChainAsync(chain, publicKeyOrResolver, options = {}) {
  // Snapshot everything before the first await; callbacks receive immutable copies.
  const copy = snapshotChain(chain);
  const anchor = checkpoint(options);
  for (const [index, block] of copy.entries()) {
    const result = await verifyBlockSignatureAsync(block, keyFor(block, index, publicKeyOrResolver));
    assertIntegrity(copy, block, index, await hashBlockAsync(block), result);
  }
  assertCheckpoint(copy, anchor);
  return true;
}
export function createSignedBlock(block, privateKey) {
  const copy = snapshotBlock(block);
  copy.signature = signBlock(copy, privateKey);
  copy.hash = hashBlock(copy);
  return copy;
}
export async function createSignedBlockAsync(block, privateKey) {
  const copy = snapshotBlock(block);
  copy.signature = await signBlockAsync(copy, privateKey);
  copy.hash = await hashBlockAsync(copy);
  return copy;
}
