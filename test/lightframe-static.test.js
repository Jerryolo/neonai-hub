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
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'id="optimization"',
    'id="optimizeButton"',
    'id="optimizerPolicyStatus"',
    'NEON-LIGHTFRAME/1.1',
    'ADAPTIVE_RENDERING_ONLY',
    'sampleGoal: 120',
    'physics_parameters_changed: false',
    'proof_gate_changed: false',
    'collectOptimizationSample(observedRenderIntervalMs'
  ]) {
    assert.ok(html.includes(required), "missing required marker: " + required);
  }
});

test("Lightframe inline application script parses", () => {
  const script = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(script, "inline application script should exist");
  assert.doesNotThrow(() => new Function(script[1]));
});

test("Auto optimization is bounded to rendering and its policy thresholds are deterministic", () => {
  const source = html.match(/function selectOptimizationProfile\(metrics\) \{[\s\S]*?\n    \}/);
  assert.ok(source, "optimizer profile policy should exist");
  const selectProfile = new Function("return (" + source[0] + ");")();

  assert.equal(selectProfile({ p95_frame_ms: 20, average_render_ms: 10 }), "QUALITY");
  assert.equal(selectProfile({ p95_frame_ms: 26, average_render_ms: 13 }), "BALANCED");
  assert.equal(selectProfile({ p95_frame_ms: 42, average_render_ms: 24 }), "ECO");

  assert.match(html, /policy: "ADAPTIVE_RENDERING_ONLY"/);
  assert.match(html, /physics_parameters_changed: false/);
  assert.match(html, /proof_gate_changed: false/);
  assert.match(html, /Nie zmienia β, transformacji Lorentza, tolerancji testu ani warunków ACT NOW \/ SILENCE/);
});

test("Lightframe HTML ids are unique and primary controls declare button type", () => {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, "duplicate HTML id");
  const buttons = [...html.matchAll(/<button\b[^>]*>/gi)].map((match) => match[0]);
  assert.ok(buttons.length >= 15, "expected interactive control set");
  for (const button of buttons) {
    assert.match(button, /\btype="button"/i);
  }
});
