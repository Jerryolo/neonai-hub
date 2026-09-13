import {createSignedBlockAsync, verifyChainAsync} from './chain.js';
import {evaluate, POLICY_VERSION} from './policy.js';

const copy = value => JSON.parse(JSON.stringify(value));
const checkpoint = ledger => ({expectedLength: ledger.length, expectedTipHash: ledger.at(-1).hash, expectedGenesisHash: ledger[0].hash});

// A session checkpoint detects truncation within this live instance. It is not an external trust anchor.
export class DemoLedger {
  constructor(keys) {
    this.keys = keys;
    this.sessionId = crypto.randomUUID();
    this.ledger = [];
    this.anchor = null;
    this.snapshot = null;
    this.locked = true;
    this.tail = Promise.resolve();
  }
  exclusive(operation) {
    const next = this.tail.then(operation);
    this.tail = next.catch(() => {});
    return next;
  }
  async initialize() {
    return this.exclusive(async () => {
      if (this.anchor) throw new Error('Session already initialized');
      const genesis = await createSignedBlockAsync({index: 0, timestamp: new Date().toISOString(), previousHash: null,
        verdict: 'GENESIS', sessionId: this.sessionId, policyVersion: POLICY_VERSION, mode: 'illustrative-no-execution'}, this.keys.privateKey);
      await verifyChainAsync([genesis], this.keys.publicKey, checkpoint([genesis]));
      this.ledger = [genesis]; this.anchor = checkpoint(this.ledger); this.locked = false;
    });
  }
  async check(records = this.ledger) {
    if (!this.anchor) throw new Error('Session not initialized');
    try { await verifyChainAsync(records, this.keys.publicKey, this.anchor); }
    catch (error) { this.locked = true; throw error; }
  }
  append(input) {
    const captured = copy(input);
    return this.exclusive(async () => {
      if (this.locked) throw new Error('Session locked');
      await this.check();
      const {operator, question, answer, confidence, risk, verified, answerSource, answerModel = null} = captured;
      for (const [name, value, max] of [['operator', operator, 80], ['question', question, 800], ['answer', answer, 16000]]) {
        if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`Invalid ${name}`);
      }
      if (!['manual offline input', 'OpenAI API'].includes(answerSource)) throw new Error('Invalid answer source');
      if (answerSource === 'OpenAI API' && (typeof answerModel !== 'string' || !answerModel.trim() || answerModel.length > 200)) throw new Error('Invalid answer model');
      if (answerSource === 'manual offline input' && answerModel !== null) throw new Error('Manual answer cannot claim an API model');
      const decision = evaluate(confidence, risk, verified);
      try {
      const block = await createSignedBlockAsync({index: this.ledger.length, timestamp: new Date().toISOString(),
        previousHash: this.anchor.expectedTipHash, sessionId: this.sessionId, operator, question, answer, confidence, risk,
        evidenceDeclaredVerified: verified, evidenceVerification: 'operator-declaration-only', answerSource, answerModel,
        policyVersion: POLICY_VERSION, mode: 'illustrative-no-execution', verdict: decision.verdict,
        reason: decision.reason, rule: decision.rule}, this.keys.privateKey);
      // Recheck the live state after asynchronous signing; never silently extend a corrupted chain.
      await this.check();
      const candidate = [...this.ledger, block];
      await verifyChainAsync(candidate, this.keys.publicKey, checkpoint(candidate));
      this.ledger = candidate; this.anchor = checkpoint(candidate);
      return {block, decision};
      } catch (error) { this.locked = true; throw error; }
    });
  }
  verify() { return this.exclusive(() => this.check()); }
  tamper() {
    return this.exclusive(async () => {
      if (this.locked) throw new Error('Session locked');
      await this.check();
      if (this.ledger.length < 2) throw new Error('Create a decision first');
      this.snapshot = copy(this.ledger);
      this.ledger[1].question += ' [ALTERED]'; this.locked = true;
      await this.check();
    });
  }
  restore() {
    return this.exclusive(async () => {
      if (!this.snapshot) throw new Error('No verified snapshot available');
      const candidate = copy(this.snapshot);
      await this.check(candidate);
      this.ledger = candidate; this.snapshot = null; this.locked = false;
    });
  }
  export() {
    return this.exclusive(async () => {
      await this.check();
      const bytes = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', this.keys.publicKey));
      const publicKeySpkiBase64 = btoa(String.fromCharCode(...bytes));
      return {format: 'pos-demo-session-v1', product: 'Proof-of-Silence™', exportedAt: new Date().toISOString(),
        signatureAlgorithm: 'Ed25519', publicKeySpkiBase64, sessionCheckpoint: copy(this.anchor),
        trust: 'Session-generated key and checkpoint; independently authenticate these before relying on external verification.',
        mode: 'illustrative-no-execution', policyVersion: POLICY_VERSION, ledger: copy(this.ledger)};
    });
  }
}

export function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  let session = null, ready = false, busy = false, offline = true;
  const controls = ['run', 'verify', 'tamper', 'restore', 'export'];
  const update = () => {
    for (const id of controls) $(id).disabled = !ready || busy || (id === 'run' && session.locked);
    $('failclosed').classList.toggle('show', ready && session.locked);
    $('offlineMode').classList.toggle('show', offline);
    $('answer').readOnly = !offline;
    $('run').textContent = offline ? 'Evaluate and sign manual answer' : 'Ask AI, evaluate, and sign';
  };
  const message = (text, css = 'rejectv') => {
    $('verdict').className = `verdict show ${css}`;
    $('verdict').textContent = text;
  };
  const render = () => {
    $('chain').replaceChildren();
    for (const block of session.ledger) {
      const node = document.createElement('div'); node.className = 'block';
      node.innerHTML = `<div class="top"><span class="idx">#${escapeHTML(block.index)}</span><span class="ts">${escapeHTML(block.timestamp)}</span><b>${escapeHTML(block.verdict)}</b></div>
        <div class="decision">Operator: ${escapeHTML(block.operator || 'Session initialization')}<br>Q: ${escapeHTML(block.question || '')}<br>A: ${escapeHTML(block.answer || '')}</div>
        <div class="hashgrid"><span class="k">PREV</span><span class="v">${escapeHTML(block.previousHash || 'GENESIS')}</span><span class="k">SHA-256</span><span class="v">${escapeHTML(block.hash)}</span><span class="k">SIGNATURE</span><span class="v">${escapeHTML(block.signature)}</span></div>`;
      $('chain').append(node);
    }
  };
  const action = operation => async () => {
    if (!ready || busy) return;
    busy = true; update();
    try { await operation(); }
    catch (error) {
      message(error.message);
      if (session.locked) {
        $('integrity').className = 'integrity bad'; $('integrity').textContent = 'INTEGRITY FAILURE · SESSION LOCKED';
      }
    } finally { busy = false; render(); update(); }
  };
  $('confidence').addEventListener('input', event => { $('confidenceValue').textContent = `${event.target.value}%`; });
  $('run').addEventListener('click', action(async () => {
    if (session.locked) throw new Error('Session locked');
    await session.verify();
    const input = {operator: $('operator').value.trim(), question: $('question').value.trim(), answer: $('answer').value.trim(),
      confidence: Number($('confidence').value), risk: $('risk').value, verified: $('verified').checked, answerSource: 'manual offline input'};
    if (!input.operator || !input.question) throw new Error('A named operator and question are required');
    evaluate(input.confidence, input.risk, input.verified);
    if (!offline) {
      try {
        const response = await fetch('/api/ask', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-NeonAI-Request': '1'},
          body: JSON.stringify({question: input.question}), signal: AbortSignal.timeout(30000)});
        const payload = await response.json();
        if (!response.ok || typeof payload.answer !== 'string' || !payload.answer.trim()) throw new Error('API unavailable');
        input.answerModel = payload.model; input.answer = payload.answer.trim(); input.answerSource = 'OpenAI API'; $('answer').value = input.answer;
      } catch {
        offline = true; $('answer').value = '';
        message('API unavailable. Enter a manual answer and submit again; no record was signed.', 'waitv'); return;
      }
    }
    const {decision} = await session.append(input);
    message(`${decision.verdict} · ${decision.reason} No external action executed.`, decision.css);
    $('integrity').className = 'integrity';
  }));
  $('verify').addEventListener('click', action(async () => {
    await session.verify(); $('integrity').className = 'integrity ok';
    $('integrity').textContent = `SESSION INTEGRITY VERIFIED · ${session.ledger.length} BLOCKS · IDENTITY NOT AUTHENTICATED`;
  }));
  $('tamper').addEventListener('click', action(() => session.tamper()));
  $('restore').addEventListener('click', action(async () => {
    await session.restore(); $('integrity').className = 'integrity'; message('Verified pre-tamper snapshot restored.', 'waitv');
  }));
  $('export').addEventListener('click', action(async () => {
    const payload = await session.export();
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'proof-of-silence-ledger.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
  (async () => {
    update();
    try {
      const keys = await crypto.subtle.generateKey({name: 'Ed25519'}, false, ['sign', 'verify']);
      session = new DemoLedger(keys); await session.initialize();
      try {
        const response = await fetch('/api/openai-status', {cache: 'no-store', signal: AbortSignal.timeout(5000)});
        if (response.ok) offline = (await response.json()).configured !== true;
      } catch { offline = true; }
      ready = true; render();
      $('cryptoNote').textContent = 'SHA-256 · Ed25519 · session-local non-exportable private key. Export includes public key and session checkpoint. No independently authenticated identity; no action execution.';
    } catch (error) {
      ready = false; $('failclosed').classList.add('show');
      $('cryptoNote').textContent = 'Cryptographic initialization failed. No signing or verification is available. Use a secure context with WebCrypto Ed25519 support.';
      message('FAIL CLOSED · Cryptography unavailable');
    }
    update();
    if (!ready) $('failclosed').classList.add('show');
  })();
}
