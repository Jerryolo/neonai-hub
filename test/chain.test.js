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

describe('verifyChain', () => {
  it('verifies hashes, continuity, and Ed25519 signatures for every block', () => {
    const { chain, publicKey } = buildChain();

    assert.equal(verifyChain(chain, publicKey), true);
  });

  it('fails signature verification when a block is tampered with', () => {
    const { chain, publicKey } = buildChain();
    const tampered = chain.map((block) => ({ ...block, data: { ...block.data } }));
    tampered[1].data.message = 'tampered';
    tampered[1].hash = hashBlock(tampered[1]);

    assert.throws(
      () => verifyChain(tampered, publicKey),
      /Chain verification failed at block 1: Ed25519 signature mismatch/,
    );
  });
});
