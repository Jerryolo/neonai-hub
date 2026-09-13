import { createServer } from 'node:http';
import { readFile, realpath } from 'node:fs/promises';
import { dirname, resolve, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const STATIC = new Map([
  ['/', 'pos-live-demo.html'], ['/pos-live-demo.html', 'pos-live-demo.html'],
  ['/src/chain.js', 'src/chain.js'], ['/src/demo.js', 'src/demo.js'],
  ['/src/policy.js', 'src/policy.js'],
]);
const fail = (status, message) => Object.assign(new Error(message), {status});
const json = (res, status, payload) => {
  res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'});
  res.end(JSON.stringify(payload));
};

async function loadKey() {
  for (const value of [process.env.OPENAI_API_KEY, process.env.OPENAI_KEY]) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  if (process.env.OPENAI_CONFIG_PATH) {
    try {
      const config = JSON.parse(await readFile(process.env.OPENAI_CONFIG_PATH, 'utf8'));
      return [config.openaiApiKey, config.OPENAI_API_KEY].find(v => typeof v === 'string' && v.trim())?.trim() || '';
    } catch { console.warn('OpenAI configuration could not be loaded. API mode disabled.'); }
  }
  return '';
}

async function readJson(req, maxBytes) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'JSON content type required.');
  if (Number(req.headers['content-length']) > maxBytes) throw fail(413, 'Request too large.');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw fail(413, 'Request too large.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw fail(400, 'Invalid JSON.'); }
}

async function boundedResponse(response, maxBytes) {
  if (Number(response.headers.get('content-length')) > maxBytes) {
    await response.body?.cancel();
    throw fail(502, 'Upstream response too large.');
  }
  if (!response.body) throw fail(502, 'Invalid upstream response.');
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw fail(502, 'Upstream response too large.');
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel().catch(() => {}); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw fail(502, 'Invalid upstream response.'); }
}

/** Local demo proxy, not a production or multi-user authorization boundary. */
export function createDemoServer({apiKey = '', model = process.env.OPENAI_MODEL || 'gpt-5.6-sol',
  fetchImpl = globalThis.fetch, root = ROOT, timeoutMs = 30_000,
  maxBodyBytes = 16_384, maxQuestionChars = 8_000, maxResponseBytes = 1_048_576,
  maxConcurrent = 2, maxRequestsPerMinute = 20} = {}) {
  let active = 0;
  let windowStart = Date.now();
  let requests = 0;
  const server = createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    try {
      const port = server.address()?.port;
      const host = req.headers.host;
      if (![`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(host)) throw fail(403, 'Host forbidden.');
      if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress)) throw fail(403, 'Loopback clients only.');
      const origin = `http://${host}`;
      if (req.headers.origin && req.headers.origin !== origin) throw fail(403, 'Origin forbidden.');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw fail(403, 'Cross-site request forbidden.');
      if (req.method === 'GET' && req.url === '/api/openai-status') {
        json(res, 200, {configured: Boolean(apiKey), model}); return;
      }
      if (req.method === 'POST' && req.url === '/api/ask') {
        if (req.headers.origin !== origin || req.headers['x-neonai-request'] !== '1') throw fail(403, 'Same-origin request required.');
        if (!apiKey) throw fail(503, 'OpenAI API key is not configured.');
        if (active >= maxConcurrent) throw fail(429, 'Too many active requests.');
        if (Date.now() - windowStart >= 60_000) { requests = 0; windowStart = Date.now(); }
        if (requests >= maxRequestsPerMinute) throw fail(429, 'Local request limit reached.');
        requests++;
        active++;
        const controller = new AbortController();
        const onClose = () => { if (!res.writableEnded) controller.abort(); };
        res.on('close', onClose);
        let timer;
        try {
          const operation = (async () => {
            const data = await readJson(req, maxBodyBytes);
            if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).some(k => k !== 'question') || typeof data.question !== 'string' || !data.question.trim() || data.question.length > maxQuestionChars) throw fail(400, 'A bounded, nonempty question string is required.');
            if (controller.signal.aborted) throw fail(504, 'Request timed out.');
            const upstream = await fetchImpl('https://api.openai.com/v1/responses', {
              method: 'POST', signal: controller.signal,
              headers: {Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json'},
              body: JSON.stringify({model, max_output_tokens: 2048, input: [{role: 'user', content: [{type: 'input_text', text: data.question}]}]}),
            });
            if (!upstream.ok) { await upstream.body?.cancel(); throw fail(502, 'OpenAI request failed.'); }
            const payload = await boundedResponse(upstream, maxResponseBytes);
            const answer = typeof payload.output_text === 'string' ? payload.output_text
              : Array.isArray(payload.output) ? payload.output.flatMap(item => Array.isArray(item?.content) ? item.content : []).filter(part => typeof part?.text === 'string').map(part => part.text).join('\n') : '';
            if (!answer) throw fail(502, 'Upstream returned no text.');
            return {model, answer};
          })();
          const deadline = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(fail(504, 'Request timed out.')); }, timeoutMs); });
          json(res, 200, await Promise.race([operation, deadline]));
        } finally {
          clearTimeout(timer); active--; res.removeListener('close', onClose);
        }
        return;
      }
      if (req.method !== 'GET') throw fail(405, 'Method not allowed.');
      const relative = STATIC.get(req.url);
      if (!relative) throw fail(404, 'Not found.');
      const filePath = resolve(root, relative);
      try {
        if (await realpath(filePath) !== filePath) throw fail(404, 'Not found.');
        const file = await readFile(filePath);
        res.writeHead(200, {'Content-Type': extname(filePath) === '.js' ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8', 'Cache-Control': 'no-store'});
        res.end(file);
      } catch { throw fail(404, 'Not found.'); }
    } catch (error) {
      if (!res.headersSent && !res.destroyed) json(res, error.status || 502, {error: error.status ? error.message : 'Request failed.'});
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.timeout = Math.max(15_000, timeoutMs + 1_000);
  server.keepAliveTimeout = 5_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const port = Number(process.env.PORT || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT.');
  const server = createDemoServer({apiKey: await loadKey()});
  server.listen(port, '127.0.0.1', () => {
    console.log(`Proof-of-Silence demo running at http://127.0.0.1:${port}`);
    console.log('Set OPENAI_API_KEY or OPENAI_CONFIG_PATH to enable API mode. OPENAI_MODEL selects the model.');
  });
}
