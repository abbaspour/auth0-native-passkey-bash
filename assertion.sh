#!/usr/bin/env bash

###############################################################################
# Author: Amin Abbaspour (pure bash implementation by Junie)
# Date: 2025-09-01
# License: LGPL 2.1 (https://github.com/abbaspour/auth0-myaccout-bash/blob/master/LICENSE)
#
# Description:
#   Build a WebAuthn assertion (get) in pure Bash using OpenSSL and jq.
#   Outputs JSON fields compatible with authentication-methods/login.sh which
#   expects:
#     - .response.authenticatorData (base64url)
#     - .response.clientDataJSON (base64url)
#     - .response.signature (base64url)
#
#   Limitations: supports EC P-256 private key (ES256) only.
###############################################################################

set -euo pipefail

command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }
command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v xxd >/dev/null || { echo >&2 "error: xxd not found"; exit 3; }

usage() {
  cat <<'END' >&2
USAGE: assertion.sh --rp <rp_id> --challenge <base64url> --username <name> --userid <id> --key <private-key.pem> --credId <base64url> [-h] [-v]

Required:
  --rp RP_ID                 # Relying Party ID / domain (e.g., example.auth0.com)
  --challenge STR            # base64url-encoded challenge
  --username NAME            # username (informational)
  --userid ID                # user handle/id (string)
  --key FILE                 # EC P-256 private key path (PEM/PKCS#8)
  --credId STR               # credential ID (base64url)

Options:
  -v                         # verbose
  -h                         # help

Example:
  ./assertion.sh --rp my-tenant.auth0.com \
    --challenge AABBCC... --username alice --userid 1234 \
    --key ./private-key.pem --credId zzz...
END
  exit ${1:-0}
}

opt_verbose=""
rp=""
challenge=""
username=""
userid=""
key_file=""
cred_id_b64url=""

# Parse long options
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rp) rp=${2:-}; shift 2 ;;
    --challenge) challenge=${2:-}; shift 2 ;;
    --username) username=${2:-}; shift 2 ;;
    --userid) userid=${2:-}; shift 2 ;;
    --key) key_file=${2:-}; shift 2 ;;
    --credId) cred_id_b64url=${2:-}; shift 2 ;;
    -v) opt_verbose=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo >&2 "Unknown argument: $1"; usage 1 ;;
  esac
done

# Validate required params
[[ -n "$rp" ]] || { echo >&2 "error: --rp is required"; usage 2; }
[[ -n "$challenge" ]] || { echo >&2 "error: --challenge is required"; usage 2; }
[[ -n "$username" ]] || { echo >&2 "error: --username is required"; usage 2; }
[[ -n "$userid" ]] || { echo >&2 "error: --userid is required"; usage 2; }
[[ -n "$key_file" ]] || { echo >&2 "error: --key is required"; usage 2; }
[[ -r "$key_file" ]] || { echo >&2 "error: key file not readable: $key_file"; exit 2; }
[[ -n "$cred_id_b64url" ]] || { echo >&2 "error: --credId is required"; usage 2; }

# Validate base64url values
validate_b64url() {
  local s="$1"
  jq -rn --arg s "$s" '$s | gsub("-"; "+") | gsub("_"; "/") | try @base64d | empty' >/dev/null 2>&1
}
if ! validate_b64url "$challenge"; then
  echo >&2 "error: --challenge is not a valid base64url string"; exit 2;
fi
if ! validate_b64url "$cred_id_b64url"; then
  echo >&2 "error: --credId is not a valid base64url string"; exit 2;
fi

# Ensure EC P-256 key to sign ES256
# Extract public key to verify curve
_tmp_pub=$(mktemp)
trap 'rm -f "$_tmp_pub"' EXIT
if ! openssl pkey -in "$key_file" -pubout -out "$_tmp_pub" >/dev/null 2>&1; then
  echo >&2 "error: failed to read private key with openssl: $key_file"; exit 2;
fi
if ! openssl ec -pubin -in "$_tmp_pub" -noout -text 2>/dev/null | grep -q 'ASN1 OID: prime256v1'; then
  echo >&2 "error: only EC P-256 (prime256v1) keys are supported"; exit 2;
fi

# Helpers
b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }
hex_of_string() { printf %s "$1" | xxd -p -c9999 | tr -d '\n' | tr 'A-F' 'a-f'; }
sha256_hex_bytes() { # stdin bytes -> hex digest
  openssl dgst -sha256 -binary | xxd -p -c9999 | tr -d '\n'
}

# Build authenticatorData for assertion
# - rpIdHash: SHA-256 of rp string (domain)
# - flags: 0x01 (User Present). We do not set UV or AT for assertion.
# - signCount: 4 bytes, we can use 00000001
rp_hash_hex=$(printf %s "$rp" | openssl dgst -sha256 -binary | xxd -p -c9999 | tr -d '\n')
flags_hex="01"
sign_cnt_hex="00000001"
auth_data_hex="${rp_hash_hex}${flags_hex}${sign_cnt_hex}"

# Build clientDataJSON with type webauthn.get
origin="https://${rp}"
client_data_json=$(jq -nc --arg chal "$challenge" --arg origin "$origin" '{type:"webauthn.get", challenge:$chal, origin:$origin}')
client_data_b64url=$(printf '%s' "$client_data_json" | b64url)

# Compute signature base: authenticatorData || SHA256(clientDataJSON)
client_data_hash_hex=$(printf '%s' "$client_data_json" | openssl dgst -sha256 -binary | xxd -p -c9999 | tr -d '\n')
sig_base_hex="${auth_data_hex}${client_data_hash_hex}"

# Sign using ECDSA with SHA-256, producing DER signature, then base64url.
# openssl pkeyutl -sign on raw digest may require -pkeyopt digest:sha256 when using pkeyutl.
# Simpler: use openssl dgst -sha256 -sign which hashes input; so we must feed raw bytes, not hex.
# Therefore convert sig_base_hex -> raw bytes and sign.
signature_der_b64url=$(printf '%s' "$sig_base_hex" | xxd -r -p | openssl dgst -sha256 -sign "$key_file" -binary | b64url)

# Encode authData as base64url
auth_data_b64url=$(printf '%s' "$auth_data_hex" | xxd -r -p | b64url)

# Output JSON to match login.sh expectations
jq -n \
  --arg authenticatorData "$auth_data_b64url" \
  --arg clientDataJSON "$client_data_b64url" \
  --arg signature "$signature_der_b64url" \
  --arg id "$cred_id_b64url" \
  --arg rawId "$cred_id_b64url" \
  --arg userId "$userid" \
  --arg userName "$username" \
  '{
    user: { id: $userId, name: $userName, displayName: $userName },
    responseDecoded: { id: $id, rawId: $rawId },
    response: { authenticatorData: $authenticatorData, clientDataJSON: $clientDataJSON, signature: $signature }
  }'
