import { createHash, sign, verify } from 'node:crypto';

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

export function verifyBlockSignature(block, publicKey) {
  if (!block.signature) {
    return { ok: false, reason: 'missing signature' };
  }

  try {
    const ok = verify(
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

export function verifyChain(chain, publicKey) {
  if (!Array.isArray(chain)) {
    throw new Error('Chain verification failed: chain must be an array');
  }

  for (const [index, block] of chain.entries()) {
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
