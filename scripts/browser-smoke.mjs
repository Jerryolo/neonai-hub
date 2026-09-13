// Run with Playwright installed: node scripts/browser-smoke.mjs
// Or PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs node scripts/browser-smoke.mjs
import assert from 'node:assert/strict';
import {createDemoServer} from '../src/openai-proxy.js';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
let upstreamCalls = 0;
const server = createDemoServer({apiKey: 'test-only-never-sent', model: 'test-model', fetchImpl: async () => {
  upstreamCalls++; return new Response(JSON.stringify({output_text: 'Mock API answer'}), {headers: {'Content-Type':'application/json'}});
}});
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
const url = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch({headless:true});
  const page = await browser.newPage();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/openai-status', route => route.fulfill({json:{configured:false}}));
  await page.goto(url);
  await page.locator('#run:enabled').waitFor();
  assert.equal(await page.locator('.block').count(),1);
  await page.locator('#operator').fill('<img src=x onerror="window.pwned=1">');
  await page.locator('#question').fill('Demo question');
  await page.locator('#answer').fill('Manual response');
  await page.locator('#verified').check();
  await page.locator('#run').click();
  await page.locator('.block').nth(1).waitFor();
  assert.equal(await page.evaluate(() => window.pwned),undefined);
  assert.equal(await page.locator('#chain img').count(),0);
  await page.locator('#verify').click();
  await page.locator('#integrity.ok').waitFor();
  const download = page.waitForEvent('download'); await page.locator('#export').click();
  const file = await (await download).path();
  const {readFile} = await import('node:fs/promises');
  const receipt = JSON.parse(await readFile(file,'utf8'));
  assert.ok(receipt.publicKeySpkiBase64); assert.equal(receipt.sessionCheckpoint.expectedLength,2);
  await page.locator('#tamper').click(); await page.locator('#integrity.bad').waitFor();
  assert.equal(await page.locator('#run').isDisabled(),true);
  await page.locator('#restore').click(); await page.locator('#run:enabled').waitFor();
  await page.locator('#verify').click(); await page.locator('#integrity.ok').waitFor();
  const online = await browser.newPage();
  await online.goto(url); await online.locator('#run:enabled').waitFor();
  await online.locator('#operator').fill('Tester'); await online.locator('#question').fill('Mock only');
  await online.locator('#run').click(); await online.locator('.block').nth(1).waitFor();
  assert.equal(upstreamCalls,1);
  const apiDownload = online.waitForEvent('download'); await online.locator('#export').click();
  const apiReceipt = JSON.parse(await readFile(await (await apiDownload).path(),'utf8'));
  assert.equal(apiReceipt.ledger[1].answerModel,'test-model'); assert.equal(apiReceipt.ledger[1].answerSource,'OpenAI API');
  const broken = await browser.newPage();
  await broken.addInitScript(() => { Object.defineProperty(crypto.subtle, 'generateKey', {value:async () => {throw new Error('Unavailable');}}); });
  await broken.goto(url); await broken.locator('#verdict.show').waitFor();
  for (const id of ['run','verify','tamper','restore','export']) assert.equal(await broken.locator(`#${id}`).isDisabled(),true);
  assert.equal(await broken.locator('.block').count(),0);
  assert.deepEqual(errors,[]);
  console.log('Browser smoke PASS: native WebCrypto, signing, export, XSS escaping, tamper/restore, boot failure.');
} finally {
  if (browser) await browser.close();
  await new Promise(resolve => server.close(resolve));
}
