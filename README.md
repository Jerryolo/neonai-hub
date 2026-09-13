# neonai-hub

A local, illustrative Proof-of-Silence™ decision ledger with SHA-256, Ed25519,
Node/WebCrypto verification, and an optional OpenAI proxy. It records operator
inputs and a deterministic demo verdict. **It does not execute actions, verify
real-world evidence, authenticate a named human, or certify compliance.**

## Run

Requires Node **22.12+** and a browser with WebCrypto Ed25519 in a secure context.
No runtime npm dependency is needed for the local server or Node tests.

```sh
npm start
```

Open http://127.0.0.1:8787 on the same computer. The server binds only to loopback.
It is deliberately not reachable from a phone over the LAN. A phone deployment
requires a separately reviewed HTTPS hosting design; this repository does not
provide an APK, PWA cache, remote authenticated service or production executor.

Without an API key, type an operator name, question and manual answer. Choose the
risk and confidence, explicitly declare the evidence status, then sign a record.
The evidence checkbox starts unchecked. Try **Verify → Try to tamper → Restore
verified snapshot → Verify → Export JSON**. Tampering blocks additional records;
restore only accepts the previously verified snapshot. Session data and keys are
lost on reload: export the ledger before closing. Manual mode makes no OpenAI calls,
but page assets still need the local server; it is not a packaged offline app.

## Optional API mode

Set `OPENAI_API_KEY` (or `OPENAI_KEY`) in your environment, or copy
`config/openai.example.json` to ignored `config/openai.json` and set
`OPENAI_CONFIG_PATH=./config/openai.json`. `OPENAI_MODEL` selects the model (default
`gpt-5.6-sol`). Availability depends on your API account; a configured key is not
proof that the model is available. Restart the server after changing configuration.
A failed API call switches the UI to manual mode without signing a fabricated answer.

Only explicit same-origin requests with the demo's custom header reach the API.
Static files use an exact allowlist; configuration and server files are not served.
The proxy limits body/question/output size, concurrent calls, requests per minute
and request duration. It is a **single-user local demo**, not authentication against
other processes on your computer. API requests happen before the illustrative
answer verdict and may incur cost; no production Proof-of-Silence execution gate is
claimed for them. The automated tests use mocked responses and make no paid calls.

## Verify an export independently

The export contains public SPKI key material, a session checkpoint, and signed
blocks. It never exports the private key. A key/checkpoint inside a document cannot
establish that document's provenance: an attacker can replace all three together.
Obtain and authenticate the expected public key and checkpoint separately from the
sender, before accepting the export. Preserve that checkpoint independently.

```sh
node src/verify-export.js proof-of-silence-ledger.json --public-key trusted-public.pem --checkpoint trusted-checkpoint.json
```

The checkpoint is JSON with `expectedLength`, `expectedTipHash`, and
`expectedGenesisHash`. The PEM must contain an Ed25519 public key. The command
ignores the export's embedded key and checkpoint when deciding trust; both external
files are mandatory. Exit codes: `0` integrity verified against supplied trust,
`1` verification failure, `2` usage error. This does not verify policy correctness,
operator identity, evidence truth, freshness beyond the supplied checkpoint, or
authorization to act. Export-envelope metadata is not independently signed; the
signed session, policy and decision fields are in each ledger block.

## Library contract

`src/chain.js` exposes synchronous Node APIs and asynchronous WebCrypto APIs:
`blockPayload`, `canonicalize`, `hashBlock[Async]`, `signBlock[Async]`,
`createSignedBlock[Async]`, `verifyBlockSignature[Async]`, `verifyChain[Async]`.

```js
verifyChain(chain, trustedPublicKey, {
  expectedLength: expectedCount,
  expectedTipHash: expectedTip,
  expectedGenesisHash: expectedGenesis,
});
```

A synchronous trusted-key resolver `(immutableBlock, index) => key` is also
supported. There is no fallback to `block.publicKey`. The caller must implement
signer allowlisting and rotation policy in that resolver. Unknown keys must fail.
PEM and native Ed25519 KeyObjects work in Node. Browser callers use Ed25519
CryptoKeys and Async methods. Non-extractable CryptoKeys must use Async methods;
the synchronous API does not convert them into exportable native key objects.

Without checkpoint options, success means **the nonempty supplied chain has valid
signatures, hashes and links**. A valid prefix still passes. Full-chain completeness
needs an externally retained tip/length; identity needs trusted key provenance.
`index`, when supplied, must match position; `previousHash` must be `null` at genesis
and the previous block's hash elsewhere. Domain-specific schema and policy validation
are the caller's responsibility. The demo signs a unique session ID and policy version.

Canonical JSON uses recursive UTF-16 property sorting, JSON string escaping and
ECMAScript number serialization, without Unicode normalization. Negative zero is
serialized as zero. Use strings for exact integers outside JavaScript's safe range.
Only finite-number JSON data is accepted: no sparse/extended arrays, class instances,
Date/Map/Set, accessors, hidden/symbol properties, cycles, undefined or lone Unicode
surrogates. `hash` and `signature` at the top level are excluded from signed/hash
payloads; the chain verifier checks the stored hash separately. Strict standard
Base64 encodes each 64-byte signature. Payload limit: 256 KiB UTF-8, depth 64;
chain limit: 1,000 blocks and 16 MiB canonical block bytes. Async verification checks
an immutable snapshot taken at invocation, not later mutations of caller state.
Inputs must be data, not hostile executable JavaScript Proxy objects. Parsing raw
JSON with duplicate keys loses those duplicates before this API; raw transport
schemas and duplicate-key rejection remain the importing application's responsibility.

The restricted data domain follows the relevant serialization rules in
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785); this is not a claim of full
cross-language conformance. The signature tests include
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) and
[Node crypto](https://nodejs.org/api/crypto.html) / WebCrypto interoperability.

## Test

```sh
npm test
npm ci --ignore-scripts
npx --no-install playwright install --with-deps chromium
npm run test:browser
```

CI runs adversarial/integration tests on Node 22 and 24 plus Chromium native
WebCrypto/UI tests. See [the security review](docs/SECURITY-REVIEW.md) for scope,
reproductions and remaining deployment boundaries. Passing tests are not proof
that no vulnerabilities exist. Review all required CI results before merging.
