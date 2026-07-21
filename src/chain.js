import { createHash, sign, verify } from 'node:crypto';

function stableStringify(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Block payload contains a non-finite number');
    }

    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(',')}}`;
  }

  throw new TypeError(`Block payload contains unsupported ${typeof value} value`);
}

export function blockPayload(block) {
  const { hash, signature, ...payload } = block;
  return stableStringify(payload);
}

export function hashBlock(block) {
  return createHash('sha256').update(blockPayload(block)).digest('hex');
}

export function signBlock(block, privateKey) {
  return sign(null, Buffer.from(blockPayload(block)), privateKey).toString('base64');
}

function decodeBase64Signature(signature) {
  if (typeof signature !== 'string' || signature.length === 0) {
    throw new TypeError('missing signature');
  }

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signature) || signature.length % 4 !== 0) {
    throw new TypeError('signature is not valid base64');
  }

  const decoded = Buffer.from(signature, 'base64');
  if (decoded.length !== 64) {
    throw new TypeError(`signature must be 64 bytes, received ${decoded.length}`);
  }

  return decoded;
}

export function verifyBlockSignature(block, publicKey) {
  if (!publicKey) {
    return { ok: false, reason: 'missing public key' };
  }

  try {
    const ok = verify(
      null,
      Buffer.from(blockPayload(block)),
      publicKey,
      decodeBase64Signature(block.signature),
    );

    return ok
      ? { ok: true }
      : { ok: false, reason: 'Ed25519 signature mismatch' };
  } catch (error) {
    return { ok: false, reason: `invalid Ed25519 signature: ${error.message}` };
  }
}

function resolveBlockPublicKey(block, index, publicKeyOrResolver) {
  if (typeof publicKeyOrResolver === 'function') {
    return publicKeyOrResolver(block, index);
  }

  return publicKeyOrResolver ?? block.publicKey;
}

export function verifyChain(chain, publicKeyOrResolver) {
  if (!Array.isArray(chain)) {
    throw new Error('Chain verification failed: chain must be an array');
  }

  for (const [index, block] of chain.entries()) {
    const publicKey = resolveBlockPublicKey(block, index, publicKeyOrResolver);
    const signatureResult = verifyBlockSignature(block, publicKey);
    if (!signatureResult.ok) {
      throw new Error(
        `Chain verification failed at block ${index}: ${signatureResult.reason}`,
      );
    }

    const actualHash = hashBlock(block);
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

  return true;
}

export function createSignedBlock(block, privateKey) {
  const unsignedBlock = { ...block };
  const signature = signBlock(unsignedBlock, privateKey);
  const signedBlock = { ...unsignedBlock, signature };

  return { ...signedBlock, hash: hashBlock(signedBlock) };
}
