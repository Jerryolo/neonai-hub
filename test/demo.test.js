import test from 'node:test';
import assert from 'node:assert/strict';
import {DemoLedger, escapeHTML} from '../src/demo.js';
import {evaluate, POLICY_VERSION} from '../src/policy.js';
import {verifyChainAsync} from '../src/chain.js';
const input = {operator: 'Tester', question: 'Approve?', answer: 'Demo only', confidence: 86, risk: 'low', verified: true, answerSource: 'manual offline input'};
async function setup() {
  const keys = await crypto.subtle.generateKey({name: 'Ed25519'}, false, ['sign', 'verify']);
  const session = new DemoLedger(keys); await session.initialize(); return session;
}
test('policy boundaries and malformed input fail closed', () => {
  for (const confidence of [NaN, Infinity, -1, 101, '90', null]) assert.throws(() => evaluate(confidence, 'low', true));
  assert.throws(() => evaluate(90, 'unknown', true));
  assert.throws(() => evaluate(90, 'low', 'true'));
  for (const [confidence, risk, verified, expected] of [[49,'low',true,'SILENCE'],[50,'low',true,'WAIT'],[79,'low',true,'WAIT'],[80,'low',true,'ACT NOW'],[100,'low',false,'SILENCE'],[100,'high',false,'REJECT'],[89,'critical',true,'REJECT'],[90,'critical',true,'WAIT'],[100,'high',true,'WAIT']]) {
    assert.equal(evaluate(confidence,risk,verified).verdict,expected);
  }
});
test('overlapping appends serialize, bind policy evidence and export public material only', async () => {
  const session = await setup();
  await Promise.all(Array.from({length: 12}, (_,i) => session.append({...input, question: `Question ${i}`})));
  assert.equal(session.ledger.length, 13); await session.verify();
  const exported = await session.export();
  assert.equal(exported.ledger[1].policyVersion, POLICY_VERSION);
  assert.equal(exported.ledger[1].confidence,86); assert.equal(exported.ledger[1].risk,'low');
  assert.equal(exported.ledger[1].evidenceDeclaredVerified,true);
  assert.equal(exported.ledger[1].answerSource,'manual offline input');
  assert.equal(exported.sessionCheckpoint.expectedLength,13);
  assert.equal(session.keys.privateKey.extractable,false);
  assert.ok(!JSON.stringify(exported).includes('PRIVATE KEY'));
  const key = await crypto.subtle.importKey('spki',Buffer.from(exported.publicKeySpkiBase64,'base64'),{name:'Ed25519'},true,['verify']);
  await verifyChainAsync(exported.ledger,key,exported.sessionCheckpoint);
});
test('truncation blocks append and restore without a snapshot cannot unlock', async () => {
  const session = await setup(); await session.append(input); session.ledger.pop();
  await assert.rejects(session.append(input)); assert.equal(session.locked,true);
  await assert.rejects(session.restore()); assert.equal(session.locked,true);
});
test('tamper blocks records; restore validates original checkpoint', async () => {
  const session = await setup(); await session.append(input);
  await assert.rejects(session.tamper()); await assert.rejects(session.append(input));
  await session.restore(); assert.equal(session.locked,false); await session.verify();
  await assert.rejects(session.tamper()); session.snapshot[1].risk='critical';
  await assert.rejects(session.restore()); assert.equal(session.locked,true);
});
test('tampered evidence cannot export', async () => {
  const session = await setup(); await session.append(input); session.ledger[1].confidence=100;
  await assert.rejects(session.export()); assert.equal(session.locked,true);
});
test('rendering escapes markup and attribute delimiters', () => {
  assert.equal(escapeHTML('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
});
test('signed sessions differ and API source model is bound to each record', async () => {
  const session = await setup(), other = await setup();
  assert.notEqual(session.ledger[0].sessionId,other.ledger[0].sessionId);
  await assert.rejects(session.append({...input,answerSource:'OpenAI API'}));
  await session.append({...input,answerSource:'OpenAI API',answerModel:'test-model',answer:'a'.repeat(2000)});
  assert.equal(session.ledger[1].sessionId,session.ledger[0].sessionId);
  assert.equal(session.ledger[1].answerModel,'test-model');
  await assert.rejects(session.append({...input,answer:'a'.repeat(16001)}));
  session.ledger[1].answerModel='imposter-model'; await assert.rejects(session.verify());
});
