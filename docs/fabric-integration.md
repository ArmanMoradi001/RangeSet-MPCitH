# Fabric integration: ledger-anchored verification flow

Status: **connection kit implemented and tested here; no live Fabric
network on this machine.** The Hyperledger network itself (test-network
or production peers) is brought up separately — see §6 runbook. This
document is the contract between the two sides: what this repo provides,
what the operator must configure, and what the ledger does and does not
guarantee.

The underlying proof system is experimental with open proof obligations
(see `docs/audit-status.md`). Nothing here upgrades that: Fabric adds
**provenance, ordering, replay protection, and access control** — never
soundness, zero knowledge, or proof of knowledge.

## 1. Architecture

```
┌──────────────┐   envelope file    ┌────────────────────────────────┐
│  rsp-prove   │ ──(ProofEnvelopeV1)─▶│  Fabric: SubmitProof           │
│  (Rust CLI)  │    + statement ID  │  status=PENDING, event emitted   │
└──────────────┘                    └───────────────┬────────────────┘
                                                    │ event
                                                    ▼
┌──────────────┐   POST /verify     ┌────────────────────────────────┐
│ Go worker *  │ ──envelope bytes──▶│  rsp-attester (Rust service)     │
│ (other host) │ ◀──JSON verdict─── │  verify_envelope vs ledger state │
└──────┬───────┘                    └────────────────────────────────┘
       │ AttestVerification(verdict, hash, reason)
       ▼
┌────────────────────────────────┐
│  Fabric: VERIFIED / REJECTED    │
└────────────────────────────────┘
```

`*` The Go event-listener/gateway worker is intentionally **not** in this
repo: it needs the live network's connection profile and is written on the
Fabric host (§6.4 specifies its exact behavior). Everything else it calls
— chaincode functions, attester HTTP API, envelope format — is frozen by
this document and tested here.

Data flow rules:

1. The ledger holds **expectations** (`StatementRecord`: range, set root,
   context, allowed params, attester MSPs). Admins register them.
2. Anyone submits **opaque envelopes**. Chaincode checks binding
   (SHA-256 of bytes == claimed hash, size cap, params allowlisted,
   proof-id uniqueness) — never proof content.
3. The attester reads the envelope + the ledger's expectation, runs the
   unmodified Rust verifier, and submits a verdict bound to the exact
   envelope hash. Only listed attester MSPs may attest, only once per
   proof, only while PENDING.

## 2. What was implemented (this repo)

| Piece | Path | Tests |
|---|---|---|
| Proof envelope + `verify_envelope` | `src/v3/envelope.rs` | `tests/v3_envelope.rs` (13) |
| Attester service logic (HTTP parse, header mapping, JSON) | `src/attester.rs` | unit tests in module (7) |
| `rsp-prove` CLI (set → prove → envelope file) | `src/bin/rsp-prove.rs` | `tests/v3_attester.rs` (CLI e2e) |
| `rsp-verify` CLI (envelope vs expectations) | `src/bin/rsp-verify.rs` | same file |
| `rsp-attester` HTTP service | `src/bin/rsp-attester.rs` | socket-level tests, same file (3) |
| Anchor chaincode | `fabric/chaincode/rangeset.go` | `rangeset_test.go` (6, MockStub) |
| Bring-up script skeleton | `fabric/e2e.sh` | run on Fabric host, not here |

No file under `src/v2`, `src/v3` (except the additive `envelope.rs` and
`mod.rs` line), `tests/v3_prototype.rs`, or the adversarial suites was
modified for this phase.

## 3. Component reference

### 3.1 Envelope (`src/v3/envelope.rs`)

Versioned binary envelope (`NMPCENV\0`, version 1): full `V3Params`,
statement fields, opaque `V3Proof` bytes (1 MiB cap), canonical BE
encoding, strict parse, BLAKE3 anchor hash. `verify_envelope` enforces,
in order: params validity → allowlist → statement-vs-expectation (6
fields) → size cap → proof parse → proof-header-vs-envelope (7 fields)
→ statement validity → `verify_combined_v3`. All rejections are typed
(`EnvelopeReject`); the proof never carries authority.

Named param presets for ledger/CLI use: `prototype-tau2`,
`reference-tau1`, `fast-insecure-test` (`named_params`).

### 3.2 Rust binaries

- `rsp-prove --value V --lo LO --hi HI --members A,B,... --member-index I
  --context HEX64 --params PRESET --seed N --out FILE` — deterministic
  for a fixed seed; prints `{"envelope_file":…,"envelope_hash":…,
  "proof_bytes":N,"envelope_bytes":M}`. Exit 0 ok / 1 prover error /
  2 usage error.
- `rsp-verify --envelope FILE --lo … --set-root … --num-members …
  --depth … --context … --allowed-params A[,B…]` — prints the fixed-shape
  JSON verdict; exit 0 iff the proof verifies.
- `rsp-attester --listen 127.0.0.1:8080` — `GET /healthz`, `POST /verify`
  (headers `X-Expected-*` + `X-Allowed-Params`, raw envelope body, 2 MiB
  cap), always HTTP 200 with `{"ok":…}` for well-formed HTTP (400 only
  for framing errors, 404 for unknown routes). Bind address is a
  deployment decision: loopback for the reference setup.

### 3.3 Chaincode (`fabric/chaincode/`)

`Init(adminMSPsCSV)` → `RegisterStatement(...)` (admin only, versioned
for root rotation) → `SubmitProof(...)` (hash-bound, allowlisted,
deduped, PENDING) → `AttestVerification(...)` (attester-MSP-gated,
hash-bound, once, flips VERIFIED/REJECTED) → `QueryProof/QueryStatement`.
Full function/error semantics are documented in the source; behavior
contract: ledger never interprets proof bytes, verdicts bind to exact
envelope hashes, decided proofs are final.

## 4. Trust model (what the ledger guarantees)

- **Provenance:** every VERIFIED proof links a ledger identity (attester
  MSP) to an exact envelope hash and a registered statement version.
- **Replay protection:** proof-id uniqueness + context binding (same
  envelope cannot be re-submitted or moved across statements/contexts).
- **Access control:** statement registration is admin-only; attestation
  is attester-MSP-only.
- **Explicitly not guaranteed:** soundness, zero knowledge, proof of
  knowledge (all NO-GO in the audit); liveness of the off-chain
  attester; privacy of submitted envelopes (proof bytes are visible to
  channel members — store only hashes on-chain plus envelopes in
  transient/private data if that matters).

## 5. Test inventory for this phase

- Rust: 7 attester unit + 3 attester service/CLI + 13 envelope tests,
  all offline; full suite `cargo test --offline` green.
- Go: 6 MockStub tests (`go test ./...`), `go vet` + `gofmt` clean.
- Not tested here (needs the other host): real endorsement, event
  delivery, gateway worker, multi-org MSPs — covered by `fabric/e2e.sh`.

## 6. Bring-up runbook (other server)

Prerequisites: Go 1.27+, Docker, `fabric-samples/test-network`, this repo
checked out at the commit recorded below (verify with
`git log --oneline -1 -- fabric/chaincode src/attester.rs`).

1. **Build Rust artifacts** (any machine, then copy):
   `cargo build --offline --release --bins` → `target/release/rsp-{prove,verify,attester}`.
2. **Start Fabric:** `./network.sh up createChannel -c mychannel -ca`
   from `fabric-samples/test-network`.
3. **Deploy chaincode:** package `fabric/chaincode` (Go, module
   `rangeset-mpcith-chaincode`), `network.sh deployCC -ccn rangeset
   -ccp <path> -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')"`,
   then `Init("Org1MSP")` via `peer chaincode invoke`.
4. **Register the statement** (as Org1 admin): `RegisterStatement` with
   the production range/root/context, `allowedParams`
   `prototype-tau2`, and the attester org's MSP id.
5. **Run the attester** on a host that reaches both a peer and the
   service port: start `rsp-attester --listen 127.0.0.1:8080`, then run
   the gateway worker loop (§6.4): on `ProofSubmitted` events, fetch the
   envelope + statement, `POST /verify`, submit `AttestVerification`.
6. **End-to-end:** `rsp-prove` → `SubmitProof` → worker attests →
   `QueryProof` shows VERIFIED; repeat with a tampered byte → REJECTED;
   re-submit the same id → duplicate rejected. `fabric/e2e.sh` encodes
   exactly this sequence (edit the connection-profile variables first).
7. **Record:** chaincode version, statement version, envelope hashes,
   and attester logs alongside the thesis results.

### 6.4 Gateway worker behavior (to implement on the Fabric host)

Subscribe to chaincode events for `ProofSubmitted`; for each new proof
id: `QueryProof` → `QueryStatement` → map statement fields to
`X-Expected-*` headers and `AllowedParams` to `X-Allowed-Params` → read
the envelope bytes (base64-decode `EnvelopeB64`) → `POST /verify` →
`AttestVerification(proofID, ok ? VERIFIED : REJECTED, envelopeHash,
reason)` signed by the attester identity. Retry transient errors;
never attest a verdict computed against any expectation other than the
ledger's current statement record.
