function getNodeCrypto() {
  return globalThis.process?.getBuiltinModule?.('node:crypto') ?? null;
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase64(bytes) {
  const byteArray = new Uint8Array(bytes);

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(byteArray).toString('base64');
  }

  let binary = '';
  for (const byte of byteArray) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(value, 'base64');
  }

  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function encodePayload(payload) {
  return new TextEncoder().encode(payload);
}

function getSubtleCrypto() {
  return globalThis.crypto?.subtle ?? null;
}

function getEd25519Algorithm() {
  return { name: 'Ed25519' };
}

export function blockPayload(block) {
  const { hash, signature, ...payload } = block;
  return stableStringify(payload);
}

export function hashBlock(block) {
  const nodeCrypto = getNodeCrypto();
  if (!nodeCrypto) {
    throw new Error('Synchronous hashBlock requires Node crypto; use hashBlockAsync in browsers');
  }

  return nodeCrypto.createHash('sha256').update(blockPayload(block)).digest('hex');
}

export async function hashBlockAsync(block) {
  const subtle = getSubtleCrypto();
  if (subtle) {
    const digest = await subtle.digest('SHA-256', encodePayload(blockPayload(block)));
    return bytesToHex(digest);
  }

  return hashBlock(block);
}

export function signBlock(block, privateKey) {
  const nodeCrypto = getNodeCrypto();
  if (!nodeCrypto) {
    throw new Error('Synchronous signBlock requires Node crypto; use signBlockAsync in browsers');
  }

  return nodeCrypto.sign(null, Buffer.from(blockPayload(block)), privateKey).toString('base64');
}

export async function signBlockAsync(block, privateKey) {
  if (privateKey?.type === 'private' || privateKey?.asymmetricKeyType === 'ed25519') {
    return signBlock(block, privateKey);
  }

  const subtle = getSubtleCrypto();
  if (!subtle) {
    return signBlock(block, privateKey);
  }

  const signature = await subtle.sign(
    getEd25519Algorithm(),
    privateKey,
    encodePayload(blockPayload(block)),
  );

  return bytesToBase64(signature);
}

export function verifyBlockSignature(block, publicKey) {
  if (!block.signature) {
    return { ok: false, reason: 'missing signature' };
  }

  const nodeCrypto = getNodeCrypto();
  if (!nodeCrypto) {
    throw new Error('Synchronous verifyBlockSignature requires Node crypto; use verifyBlockSignatureAsync in browsers');
  }

  try {
    const ok = nodeCrypto.verify(
      null,
      Buffer.from(blockPayload(block)),
      publicKey,
      Buffer.from(block.signature, 'base64'),
    );

    return ok
      ? { ok: true }
      : { ok: false, reason: 'Ed25519 signature mismatch' };
  } catch (error) {
    return { ok: false, reason: `invalid Ed25519 signature: ${error.message}` };
  }
}

export async function verifyBlockSignatureAsync(block, publicKey) {
  if (!block.signature) {
    return { ok: false, reason: 'missing signature' };
  }

  if (publicKey?.type === 'public' || publicKey?.asymmetricKeyType === 'ed25519') {
    return verifyBlockSignature(block, publicKey);
  }

  const subtle = getSubtleCrypto();
  if (!subtle) {
    return verifyBlockSignature(block, publicKey);
  }

  try {
    const ok = await subtle.verify(
      getEd25519Algorithm(),
      publicKey,
      base64ToBytes(block.signature),
      encodePayload(blockPayload(block)),
    );

    return ok
      ? { ok: true }
      : { ok: false, reason: 'Ed25519 signature mismatch' };
  } catch (error) {
    return { ok: false, reason: `invalid Ed25519 signature: ${error.message}` };
  }
}

function assertChain(chain) {
  if (!Array.isArray(chain)) {
    throw new Error('Chain verification failed: chain must be an array');
  }
}

function assertSignatureResult(signatureResult, index) {
  if (!signatureResult.ok) {
    throw new Error(
      `Chain verification failed at block ${index}: ${signatureResult.reason}`,
    );
  }
}

function assertBlockIntegrity(chain, block, index, actualHash) {
  if (block.hash !== actualHash) {
    throw new Error(
      `Chain verification failed at block ${index}: SHA-256 hash mismatch`,
    );
  }

  const expectedPreviousHash = index === 0 ? null : chain[index - 1].hash;
  if (block.previousHash !== expectedPreviousHash) {
    throw new Error(
      `Chain verification failed at block ${index}: previousHash does not match block ${index - 1}`,
    );
  }
}

export function verifyChain(chain, publicKey) {
  assertChain(chain);

  for (const [index, block] of chain.entries()) {
    assertSignatureResult(verifyBlockSignature(block, publicKey), index);
    assertBlockIntegrity(chain, block, index, hashBlock(block));
  }

  return true;
}

export async function verifyChainAsync(chain, publicKey) {
  assertChain(chain);

  for (const [index, block] of chain.entries()) {
    assertSignatureResult(await verifyBlockSignatureAsync(block, publicKey), index);
    assertBlockIntegrity(chain, block, index, await hashBlockAsync(block));
  }

  return true;
}

export function createSignedBlock(block, privateKey) {
  const unsignedBlock = { ...block };
  const signature = signBlock(unsignedBlock, privateKey);
  const signedBlock = { ...unsignedBlock, signature };

  return { ...signedBlock, hash: hashBlock(signedBlock) };
}

export async function createSignedBlockAsync(block, privateKey) {
  const unsignedBlock = { ...block };
  const signature = await signBlockAsync(unsignedBlock, privateKey);
  const signedBlock = { ...unsignedBlock, signature };

  return { ...signedBlock, hash: await hashBlockAsync(signedBlock) };
}
