import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const url = new URL("../experiments/neon-lightframe.html", import.meta.url);
const html = await readFile(url, "utf8");

test("Lightframe remains a portable single-file offline artifact", () => {
  assert.ok(Buffer.byteLength(html, "utf8") < 100 * 1024, "artifact should stay phone-friendly");
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(html, /<script\s+[^>]*\bsrc\s*=/i);
  assert.doesNotMatch(html, /<link\s+[^>]*\bhref\s*=/i);
  assert.doesNotMatch(html, /\bfetch\s*\(/);
  assert.doesNotMatch(html, /\bXMLHttpRequest\b/);
  assert.doesNotMatch(html, /\bWebSocket\b/);
  assert.doesNotMatch(html, /\bEventSource\b/);
  assert.doesNotMatch(html, /https?:\/\//i);
});

test("Lightframe states the scientific limits instead of drawing misleading conclusions", () => {
  assert.match(html, /nie falisty tor fotonu/i);
  assert.match(html, /nie jest trajektorią fotonu/i);
  assert.match(html, /nie fotografia fotonu/i);
  assert.match(html, /nie eksperyment fizyczny/i);
  assert.match(html, /NO_SENSOR_EVIDENCE/);
  assert.match(html, /SIMULATION_ONLY/);
  assert.match(html, /NIEPODPISANY REKORD LOKALNY/);
  assert.match(html, /Hash wykrywa zmianę danych po zamknięciu/);
});

test("Lightframe includes the invariant, challenge, gate, and local receipt controls", () => {
  for (const required of [
    'id="velocity"',
    'min="-0.95"',
    'max="0.95"',
    'id="lightScene"',
    'id="coneCanvas"',
    'id="lensCanvas"',
    'id="challengeButton"',
    'id="sealButton"',
    'id="verifyButton"',
    'id="exportButton"',
    '"ACT NOW"',
    '"SILENCE"',
    'samples = 10000',
    'tolerance = 1e-12',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  ]) {
    assert.ok(html.includes(required), "missing required marker: " + required);
  }
});

test("Lightframe HTML ids are unique and primary controls declare button type", () => {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, "duplicate HTML id");
  const buttons = [...html.matchAll(/<button\b[^>]*>/gi)].map((match) => match[0]);
  assert.ok(buttons.length >= 18, "expected interactive control set");
  for (const button of buttons) {
    assert.match(button, /\btype="button"/i);
  }
});
