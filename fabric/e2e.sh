#!/usr/bin/env bash
# Fabric end-to-end smoke script — RUN ON THE FABRIC HOST, NOT HERE.
# It needs: fabric-samples/test-network up, deployed `rangeset` chaincode,
# a running rsp-attester, peer binaries + connection profile in env.
# Edit the CONFIG block first, then: bash fabric/e2e.sh
set -euo pipefail

# ---------------- CONFIG (edit me) ----------------
CHANNEL="${CHANNEL:-mychannel}"
CC_NAME="${CC_NAME:-rangeset}"
ATTESTER_URL="${ATTESTER_URL:-http://127.0.0.1:8080}"
RSP_PROVE="${RSP_PROVE:-./target/release/rsp-prove}"
RSP_VERIFY="${RSP_VERIFY:-./target/release/rsp-verify}"
WORKDIR="${WORKDIR:-/tmp/rsp-e2e}"
# peer CLI env (test-network Org1 admin); adjust for your topology.
export CORE_PEER_LOCALMSPID="${CORE_PEER_LOCALMSPID:-Org1MSP}"
# --------------------------------------------------

log() { echo "[e2e] $*"; }
need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 2; }; }

need peer
need curl
[ -x "$RSP_PROVE" ] || { echo "missing binary: $RSP_PROVE"; exit 2; }
[ -x "$RSP_VERIFY" ] || { echo "missing binary: $RSP_VERIFY"; exit 2; }

invoke() { peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C "$CHANNEL" -n "$CC_NAME" "$@"; }
query() { peer chaincode query -C "$CHANNEL" -n "$CC_NAME" "$@"; }

mkdir -p "$WORKDIR"
CONTEXT="0707070707070707070707070707070707070707070707070707070707070707"

log "1. prove honest envelope and read back its root + hash"
"$RSP_PROVE" --value 20 --lo 10 --hi 40 --members 10,20,30,40 --member-index 1 \
  --context "$CONTEXT" --params fast-insecure-test --seed 4242 --out "$WORKDIR/proof.env"
# Envelope layout: magic 8 + version 2 + params 24 + lo 4 + hi 4, then root 32.
ROOT_HEX=$(python3 - "$WORKDIR/proof.env" <<'EOF'
import sys
data = open(sys.argv[1],'rb').read()
print(data[8+2+24+4+4:8+2+24+4+4+32].hex())
EOF
)
ENVELOPE_B64=$(base64 -w0 "$WORKDIR/proof.env")
# Canonical envelope hash comes from the verifier itself (BLAKE3 digest).
ENVELOPE_HASH=$("$RSP_VERIFY" --envelope "$WORKDIR/proof.env" --lo 10 --hi 40 \
  --set-root "$ROOT_HEX" --num-members 4 --depth 2 --context "$CONTEXT" \
  --allowed-params fast-insecure-test | python3 -c "import json,sys; print(json.load(sys.stdin)['envelope_hash'])")

log "2. register statement (admin)"
invoke --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  -c "{\"Args\":[\"RegisterStatement\",\"stmt-e2e\",\"10\",\"40\",\"$ROOT_HEX\",\"4\",\"2\",\"$CONTEXT\",\"fast-insecure-test\",\"AttesterMSP\"]}" >/dev/null

log "3. submit honest proof"
invoke --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  -c "{\"Args\":[\"SubmitProof\",\"proof-e2e-1\",\"stmt-e2e\",\"$ENVELOPE_HASH\",\"$ENVELOPE_B64\",\"fast-insecure-test\"]}" >/dev/null

log "4. off-chain verify (simulates gateway worker fetch)"
curl -sf "$ATTESTER_URL/healthz" >/dev/null
curl -sf -X POST "$ATTESTER_URL/verify" \
  -H "X-Expected-Range-Lo: 10" -H "X-Expected-Range-Hi: 40" \
  -H "X-Expected-Set-Root: $ROOT_HEX" -H "X-Expected-Num-Members: 4" \
  -H "X-Expected-Depth: 2" -H "X-Expected-Context: $CONTEXT" \
  -H "X-Allowed-Params: fast-insecure-test" \
  --data-binary "@$WORKDIR/proof.env" -o "$WORKDIR/verdict.json"
grep -q '"ok":true' "$WORKDIR/verdict.json"

log "5. attest VERIFIED (as attester identity) then query"
# NOTE: run step 5 with the attester org's peer CLI env / identity.
invoke --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  -c "{\"Args\":[\"AttestVerification\",\"proof-e2e-1\",\"VERIFIED\",\"$ENVELOPE_HASH\",\"e2e honest\"]}" >/dev/null
query -c '{"Args":["QueryProof","proof-e2e-1"]}' | grep -q '"status":"VERIFIED"'

log "6. tampered copy must verify false off-chain (negative control)"
python3 - "$WORKDIR/proof.env" "$WORKDIR/tampered.env" <<'EOF'
import sys
data = bytearray(open(sys.argv[1],'rb').read())
data[-1] ^= 1
open(sys.argv[2],'wb').write(bytes(data))
EOF
"$RSP_VERIFY" --envelope "$WORKDIR/tampered.env" --lo 10 --hi 40 \
  --set-root "$ROOT_HEX" --num-members 4 --depth 2 --context "$CONTEXT" \
  --allowed-params fast-insecure-test > "$WORKDIR/verdict-bad.json" && {
  echo "negative control FAILED: tampered envelope verified"; exit 1; }
grep -q '"ok":false' "$WORKDIR/verdict-bad.json"

log "7. duplicate submit must be rejected"
if invoke --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  -c "{\"Args\":[\"SubmitProof\",\"proof-e2e-1\",\"stmt-e2e\",\"$ENVELOPE_HASH\",\"$ENVELOPE_B64\",\"fast-insecure-test\"]}" 2>/dev/null; then
  echo "duplicate submit accepted"; exit 1
fi

log "E2E OK"
