import {readFile, stat} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {verifyChain} from './chain.js';

async function boundedFile(path, maxBytes) {
  if ((await stat(path)).size > maxBytes) throw new Error('File exceeds verification limit');
  const data = await readFile(path, 'utf8');
  if (Buffer.byteLength(data) > maxBytes) throw new Error('File exceeds verification limit');
  return data;
}

// Trust material must come from outside the document being verified.
export async function verifyExportFile(exportPath, publicKeyPath, checkpointPath) {
  const document = JSON.parse(await boundedFile(exportPath, 17 * 1024 * 1024));
  if (!document || document.format !== 'pos-demo-session-v1' || document.signatureAlgorithm !== 'Ed25519') {
    throw new Error('Unsupported export format');
  }
  const key = createPublicKey(await boundedFile(publicKeyPath, 16384));
  const checkpoint = JSON.parse(await boundedFile(checkpointPath, 4096));
  if (!checkpoint || !Object.hasOwn(checkpoint, 'expectedLength') || !Object.hasOwn(checkpoint, 'expectedTipHash') || !Object.hasOwn(checkpoint, 'expectedGenesisHash')) {
    throw new Error('Trusted checkpoint requires expectedLength, expectedTipHash and expectedGenesisHash');
  }
  verifyChain(document.ledger, key, checkpoint);
  return {status: 'INTEGRITY_VERIFIED', blocks: document.ledger.length,
    scope: 'Signatures, hashes, links and externally supplied checkpoint',
    note: 'Signer identity depends on key provenance. Policy correctness and action authorization are not verified.'};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [exportPath, keyFlag, keyPath, checkpointFlag, checkpointPath, ...extra] = process.argv.slice(2);
  if (!exportPath || keyFlag !== '--public-key' || !keyPath || checkpointFlag !== '--checkpoint' || !checkpointPath || extra.length) {
    console.error('Usage: node src/verify-export.js export.json --public-key trusted-public.pem --checkpoint trusted-checkpoint.json');
    process.exitCode = 2;
  } else {
    try { console.log(JSON.stringify(await verifyExportFile(exportPath, keyPath, checkpointPath))); }
    catch (error) { console.error(JSON.stringify({status: 'FAIL', reason: error.message})); process.exitCode = 1; }
  }
}
