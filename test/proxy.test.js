import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { createDemoServer } from '../src/openai-proxy.js';

async function fixture(t, options = {}) {
  let calls = 0;
  const server = createDemoServer({apiKey: 'TEST-SECRET-NEVER-EXPOSE', fetchImpl: async () => {
    calls++; return new Response(JSON.stringify({output_text: 'Mock answer'}));
  }, ...options});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); return new Promise(r => server.close(r)); });
  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;
  const send = (path, {method = 'GET', headers = {}, body = ''} = {}) => new Promise((resolve, reject) => {
    const req = request({hostname: '127.0.0.1', port, path, method, headers}, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({status: res.statusCode, body: Buffer.concat(chunks).toString(), headers: res.headers}));
    });
    req.on('error', reject); req.end(body);
  });
  const post = (overrides = {}) => send('/api/ask', {method: 'POST', body: JSON.stringify({question: 'Hello'}), ...overrides,
    headers: {Origin: origin, 'Content-Type': 'application/json', 'X-NeonAI-Request': '1', ...overrides.headers}});
  return {server, send, post, origin, calls: () => calls};
}

test('proxy serves only named public assets and hides secrets/source/config', async t => {
  const {send, calls} = await fixture(t);
  assert.equal((await send('/')).status, 200);
  for (const path of ['/.env', '/.git/config', '/src/openai-proxy.js', '/package.json', '/README.md', '/../.env', '/%2e%2e/.env', '//.env', '/pos-live-demo.html?x=1']) {
    const result = await send(path);
    assert.equal(result.status, 404, path);
    assert.ok(!result.body.includes('TEST-SECRET'));
  }
  const status = await send('/api/openai-status');
  assert.deepEqual(JSON.parse(status.body), {configured: true, model: 'gpt-5.6-sol'});
  assert.equal(calls(), 0);
});

test('proxy rejects DNS rebinding, foreign/null origins, missing origin/header and CORS preflight', async t => {
  const {send, post, calls} = await fixture(t);
  assert.equal((await send('/', {headers: {Host: 'attacker.example'}})).status, 403);
  for (const headers of [{Origin: 'https://attacker.example'}, {Origin: 'null'}, {Origin: ''}, {'X-NeonAI-Request': ''}, {'Sec-Fetch-Site': 'cross-site'}]) {
    assert.equal((await post({headers})).status, 403);
  }
  const preflight = await send('/api/ask', {method: 'OPTIONS', headers: {Origin: 'https://attacker.example'}});
  assert.equal(preflight.status, 403);
  assert.equal(preflight.headers['access-control-allow-origin'], undefined);
  assert.equal(calls(), 0);
});

test('proxy bounds/validates requests before upstream use', async t => {
  const {post, calls} = await fixture(t, {maxBodyBytes: 100, maxQuestionChars: 10});
  assert.equal((await post({headers: {'Content-Type': 'text/plain'}})).status, 415);
  for (const body of ['{', 'null', '[]', '{}', '{"question":42}', '{"question":" "}', '{"question":"12345678901"}', '{"question":"hi","model":"other"}']) {
    assert.equal((await post({body})).status, 400, body);
  }
  assert.equal((await post({body: 'x'.repeat(101)})).status, 413);
  assert.equal(calls(), 0);
});

test('proxy mock request succeeds and applies model/token constraints', async t => {
  let captured;
  const {post} = await fixture(t, {model: 'test-model', fetchImpl: async (url, options) => {
    captured = {url, ...options};
    return new Response(JSON.stringify({output: [{content: [{text: 'Mock output'}]}]}));
  }});
  const result = await post();
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), {model: 'test-model', answer: 'Mock output'});
  assert.equal(captured.url, 'https://api.openai.com/v1/responses');
  assert.equal(JSON.parse(captured.body).max_output_tokens, 2048);
  assert.equal(JSON.parse(captured.body).model, 'test-model');
});

test('proxy sanitizes upstream errors and rejects malformed/oversized output', async t => {
  for (const response of [() => new Response('TEST-SECRET exception', {status: 401}), () => new Response('bad json'), () => new Response(JSON.stringify({output_text: 'x'.repeat(200)}))]) {
    const {post} = await fixture(t, {maxResponseBytes: 100, fetchImpl: async () => response()});
    const result = await post();
    assert.equal(result.status, 502);
    assert.ok(!result.body.includes('TEST-SECRET'));
  }
  const {post} = await fixture(t, {fetchImpl: async () => { throw new Error('TEST-SECRET'); }});
  const result = await post();
  assert.equal(result.status, 502);
  assert.ok(!result.body.includes('TEST-SECRET'));
});

test('proxy aborts timed-out upstream and bounds concurrency', async t => {
  let aborted = false;
  let started;
  const began = new Promise(resolve => { started = resolve; });
  const {post} = await fixture(t, {timeoutMs: 60, maxConcurrent: 1, fetchImpl: async (_, {signal}) => {
    started();
    return new Promise((_, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('abort')); }, {once: true}));
  }});
  const first = post();
  await began;
  assert.equal((await post()).status, 429);
  assert.equal((await first).status, 504);
  assert.equal(aborted, true);
});

test('proxy limits repeated billed requests and disables API without key', async t => {
  const {post, calls} = await fixture(t, {maxRequestsPerMinute: 1});
  assert.equal((await post()).status, 200);
  assert.equal((await post()).status, 429);
  assert.equal(calls(), 1);
  const disabled = await fixture(t, {apiKey: ''});
  assert.equal((await disabled.post()).status, 503);
  assert.equal((await disabled.send('/')).status, 200);
  assert.equal(disabled.calls(), 0);
});
