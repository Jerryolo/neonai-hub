import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';

import { createSignedBlock, hashBlock, verifyChain } from '../src/chain.js';

function buildChain() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const genesis = createSignedBlock(
    { index: 0, timestamp: 1, previousHash: null, data: { message: 'genesis' } },
    privateKey,
  );
  const second = createSignedBlock(
    { index: 1, timestamp: 2, previousHash: genesis.hash, data: { message: 'second' } },
    privateKey,
  );

  return { chain: [genesis, second], publicKey };
}

function cloneChain(chain) {
  return chain.map((block) => ({ ...block, data: { ...block.data } }));
}

describe('verifyChain', () => {
  it('verifies hashes, continuity, and Ed25519 signatures for every block', () => {
    const { chain, publicKey } = buildChain();

    assert.equal(verifyChain(chain, publicKey), true);
  });

  it('fails signature verification when any block is tampered with', () => {
    const { chain, publicKey } = buildChain();

    for (const index of chain.keys()) {
      const tampered = cloneChain(chain);
      tampered[index].data.message = 'tampered';
      tampered[index].hash = hashBlock(tampered[index]);

      assert.throws(
        () => verifyChain(tampered, publicKey),
        new RegExp(`Chain verification failed at block ${index}: Ed25519 signature mismatch`),
      );
    }
  });

  it('reports the specific block when its signature is malformed', () => {
    const { chain, publicKey } = buildChain();
    const tampered = cloneChain(chain);
    tampered[1].signature = 'not base64';

    assert.throws(
      () => verifyChain(tampered, publicKey),
      /Chain verification failed at block 1: invalid Ed25519 signature: signature is not valid base64/,
    );
  });
});
