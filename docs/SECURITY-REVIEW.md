# Red team / blue team review — 2026-09-13

Scope: all tracked source and configuration in `Jerryolo/neonai-hub`, PR #6 head
`7e3e15a6f8f2cf44e453c7c84c44f1badc7d7232`, integrated with main
`649f325a3238659f954d3d2dd390380a83dbce26`. Includes chain library, browser demo,
proxy, export verifier and CI. No production service, Shopify, other repository,
external account, mobile device or paid API call was tested. No claim is made that
this constitutes an audit of the founder's entire Proof-of-Silence ecosystem.

## Findings and fixes

| Red-team observation | Blue-team correction | Evidence |
| --- | --- | --- |
| PR verifier accepts attacker's embedded signing key when external key is omitted | Explicit external trusted key/resolver, Ed25519 type/role checks | `test/crypto-redteam.test.js` |
| PR accepts P-256 ECDSA with 64-byte P1363 signature | Reject key option bags and all non-Ed25519 keys | crypto tests |
| Empty chain returns true | `EMPTY_CHAIN` rejects in both APIs | crypto tests |
| Sparse arrays and distinct Date objects produce identical signed bytes | Validated restricted JSON data domain; no getters or class hooks | crypto tests |
| Base64 padding-bit changes accepted | Exact 64-byte decode/re-encode equality | crypto tests |
| Valid prefix passes after tail removal | Optional externally trusted genesis/tip/length; mandatory in demo and export CLI | crypto, demo and export tests |
| Main incorrectly routes browser CryptoKeys to Node sync crypto because both have type private/public | Genuine CryptoKey detection, WebCrypto async path | Node/WebCrypto parity; browser smoke gate |
| Main proxy serves project files and binds all interfaces | Exact public-asset allowlist, no symlink serving, loopback-only CLI | Local baseline read returned HTTP 200 for a fake API-key marker; fixed proxy tests reject private paths |
| API has no origin boundary, request/output limits or timeout | Host, remote-address, Origin and custom-header checks; input/output, time, rate and concurrency bounds | mocked HTTP regression tests |
| Browser can race signing, start before crypto ready, restore without validating snapshot, and export without public key | Startup lock, serialized operations, anchored checks before/after append, verified restore, public-key/checkpoint export | demo integration tests and browser gate |
| Risk, confidence and answer provenance absent from signed data | Signed policy version, session ID, evidence declaration, risk/confidence, source/model | demo tests |
| UI implies actual evidence authentication or action execution | Explicit illustrative/no-execution mode; evidence is operator declaration only | UI copy and signed mode |
| PR conflicted with browser/proxy additions on main | Merge main into PR lineage and preserve sync + async functionality | two-parent merge commit and complete regression suite |

Additional CI finding: initial hardening commit `4aea826` passed Node 24 and
Chromium but failed the Node 22 low-order-key forgery test. The follow-up adds
explicit checks for all compressed small-order y encodings (both sign bits),
noncanonical y and S encodings, and validates public-key bytes before native
verification. Browser public CryptoKeys must be exportable for these public-data
checks; private keys remain non-exportable. No failing test was removed or skipped.

## Executed verification

Local Node v24.19.0: **49 tests passed**, comprising 3 original PR tests, 31 crypto
red-team tests, 7 demo/policy tests, 7 proxy HTTP suites and 1 end-to-end export CLI
suite. Tests include RFC 8032 known-answer checks, independent hash/link rejection,
key/algorithm substitution, malformed canonical inputs, identity/low-order forgery,
S+L scalar malleability, truncated chains, source provenance, 12 concurrent appends,
unsafe restore, secret paths, cross-site requests, bounds/timeouts, and mocked API
success/failure. Cryptographic backend coverage locally is Node/OpenSSL and Node
WebCrypto, not all browser implementations.

Local Chromium execution was initially blocked by absence of the browser binary;
standard Playwright installation timed out. The first CI run subsequently passed
the actual Chromium UI smoke test on `4aea826`; the follow-up must pass again. `scripts/browser-smoke.mjs` is provided
and the required CI browser job installs Chromium and exercises the actual UI,
native WebCrypto, export, XSS escaping, tamper/restore, missing-crypto boot, and the
same-origin proxy request with a mock upstream. **Do not interpret script creation
as a browser PASS: use the CI result attached to the exact reviewed commit.**

## Remaining boundaries / merge gate

- This is a local session demonstrator. Reload loses session state. Private keys
  are ephemeral; no durable append-only storage, production key custody/rotation,
  capability tokens, replay-protected executor, distributed ledger serialization,
  authenticated operator or independent evidence validation is implemented.
- The local API proxy is not a production security boundary against local software.
  Authorized UI requests may spend API credits before the illustrative answer
  verdict. There is no assertion that a PoS gate authorizes that network call.
- Freshness/completeness requires a checkpoint obtained independently. A public
  key embedded in an export is descriptive, not inherently trusted. The verifier
  does not prove when a signed event occurred or whether its evidence is true.
- Hostile same-process code, compromised browser extensions, OS compromise, stolen
  signing keys, and malicious arbitrary JavaScript Proxy inputs are outside this
  data-verification boundary. No automated test proves universal crypto safety.
- Phone/Android compatibility and live OpenAI model/account availability remain
  untested. No production deployment or merge is performed by this patch.
- Before merge: green Node 22, Node 24 and Chromium jobs on the updated PR head;
  maintainer review of the stricter API/data contract and local-only behavior.
  Configure these checks as required in repository rules if they are not already.
