#!/usr/bin/env bash

###############################################################################
# Author: Amin Abbaspour (pure bash implementation by Junie)
# Date: 2025-08-28
# License: LGPL 2.1 (https://github.com/abbaspour/auth0-myaccout-bash/blob/master/LICENSE)
#
# Description:
#   Build a WebAuthn attestation object in pure Bash (no Go), using OpenSSL and jq.
#   We generate a "none" attestation (fmt: none, attStmt: {}), and construct a
#   valid authenticator data (authData) including a COSE_Key derived from the
#   provided EC P-256 private key. Output JSON matches fields used by
#   enroll-authentication-methods.sh:
#     - .response.attestationObject (base64url)
#     - .response.clientDataJSON (base64url)
#     - .responseDecoded.rawId (base64url credential ID)
#
#   Limitations: this implementation supports EC P-256 with ES256 only.
###############################################################################

set -euo pipefail

command -v jq >/dev/null || { echo >&2 "error: jq not found"; exit 3; }
command -v openssl >/dev/null || { echo >&2 "error: openssl not found"; exit 3; }
command -v xxd >/dev/null || { echo >&2 "error: xxd not found"; exit 3; }

readonly DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  cat <<'END' >&2
USAGE: attestation.sh --rp <rp_id> --challenge <base64url> --username <name> --userid <id> --key <private-key.pem> [-h] [-v]

Required:
  --rp RP_ID                 # Relying Party ID / domain (e.g., example.auth0.com)
  --challenge STR            # base64url-encoded challenge
  --username NAME            # username
  --userid ID                # user id (string)
  --key FILE                 # EC P-256 private key path (PEM/PKCS#8)

Options:
  -v                         # verbose
  -h                         # help

Example:
  ./attestation.sh --rp my-tenant.auth0.com \
    --challenge AABBCC... --username alice --userid 1234 \
    --key ./private-key.pem
END
  exit ${1:-0}
}

opt_verbose=""
rp=""
challenge=""
username=""
userid=""
key_file=""

# Parse long options manually for portability
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rp) rp=${2:-}; shift 2 ;;
    --challenge) challenge=${2:-}; shift 2 ;;
    --username) username=${2:-}; shift 2 ;;
    --userid) userid=${2:-}; shift 2 ;;
    --key) key_file=${2:-}; shift 2 ;;
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

# Validate challenge is base64url
if ! jq -rn --arg s "$challenge" '$s | gsub("-"; "+") | gsub("_"; "/") | try @base64d | empty' >/dev/null 2>&1; then
  echo >&2 "error: --challenge is not a valid base64url string"
  exit 2
fi

# Ensure EC P-256 key and extract uncompressed pubkey point (04 || X || Y)
tmp_pub=$(mktemp)
trap 'rm -f "$tmp_pub"' EXIT

# Extract public key PEM from any PEM private key
if ! openssl pkey -in "$key_file" -pubout -out "$tmp_pub" >/dev/null 2>&1; then
  echo >&2 "error: failed to read private key with openssl: $key_file"
  exit 2
fi

# Verify curve is prime256v1
if ! openssl ec -pubin -in "$tmp_pub" -noout -text 2>/dev/null | grep -q 'ASN1 OID: prime256v1'; then
  echo >&2 "error: only EC P-256 (prime256v1) keys are supported"
  exit 2
fi

# Get uncompressed public point hex (starts with 04)
pub_point_hex=$(openssl ec -pubin -in "$tmp_pub" -text -noout 2>/dev/null \
  | awk '/pub:/{flag=1;next}/ASN1 OID|NIST CURVE/{flag=0}flag' \
  | tr -d ' \n:' | tr 'A-F' 'a-f')
if [[ -z "$pub_point_hex" || ${pub_point_hex:0:2} != "04" ]]; then
  echo >&2 "error: failed to extract EC public point"
  exit 2
fi
X_HEX=${pub_point_hex:2:64}
Y_HEX=${pub_point_hex:66:64}

# Helpers
hex_of_string() { printf %s "$1" | xxd -p -c9999 | tr -d '\n' | tr 'A-F' 'a-f'; }
raw_b64url_from_hex() { xxd -r -p | openssl base64 -A | tr -d '=' | tr '+/' '-_'; }
sha256_hex() { printf %s "$1" | openssl dgst -sha256 -binary | xxd -p -c9999 | tr -d '\n'; }
rand_hex() { openssl rand -hex "$1" | tr -d '\n'; }

# CBOR helpers (emit lowercase hex)
cbor_uint() { # arg: decimal
  local n=$1
  if (( n < 24 )); then printf '%02x' $((0x00 + n)); else
    if (( n < 256 )); then printf '18%02x' $n; elif (( n < 65536 )); then printf '19%04x' $n; else printf '1a%08x' $n; fi
  fi
}
cbor_nint() { # arg: negative integer value (e.g., -1)
  local v=$1
  local n=$(( -1 - v ))
  if (( n < 24 )); then printf '%02x' $((0x20 + n)); else
    if (( n < 256 )); then printf '38%02x' $n; elif (( n < 65536 )); then printf '39%04x' $n; else printf '3a%08x' $n; fi
  fi
}
cbor_tstr() { # arg: ascii string
  local s="$1"
  local hex; hex=$(hex_of_string "$s")
  local len=$(( ${#hex} / 2 ))
  if (( len < 24 )); then printf '%02x%s' $((0x60 + len)) "$hex"; else
    if (( len < 256 )); then printf '78%02x%s' $len "$hex"; elif (( len < 65536 )); then printf '79%04x%s' $len "$hex"; else printf '7a%08x%s' $len "$hex"; fi
  fi
}
cbor_bstr() { # arg: hex bytes content
  local hex="$1"; local len=$(( ${#hex} / 2 ))
  if (( len < 24 )); then printf '%02x%s' $((0x40 + len)) "$hex"; else
    if (( len < 256 )); then printf '58%02x%s' $len "$hex"; elif (( len < 65536 )); then printf '59%04x%s' $len "$hex"; else printf '5a%08x%s' $len "$hex"; fi
  fi
}
cbor_map_start() { # arg: size
  local n=$1
  if (( n < 24 )); then printf '%02x' $((0xa0 + n)); else
    if (( n < 256 )); then printf 'b8%02x' $n; elif (( n < 65536 )); then printf 'b9%04x' $n; else printf 'ba%08x' $n; fi
  fi
}

# Build COSE_Key for ES256: {1:2, 3:-7, -1:1, -2:X, -3:Y}
make_cose_key_hex() {
  local xhex="$1" yhex="$2"
  local out=""
  out+=$(cbor_map_start 5)
  out+=$(cbor_uint 1)    # key 1
  out+=$(cbor_uint 2)    # kty EC2
  out+=$(cbor_uint 3)    # key 3
  out+=$(cbor_nint -7)   # alg ES256
  out+=$(cbor_nint -1)   # key -1
  out+=$(cbor_uint 1)    # crv P-256
  out+=$(cbor_nint -2)   # key -2
  out+=$(cbor_bstr "$xhex")
  out+=$(cbor_nint -3)   # key -3
  out+=$(cbor_bstr "$yhex")
  printf '%s' "$out"
}

# Build authenticator data
rp_hash_hex=$(sha256_hex "$rp")
flags_hex="41"   # UP (0x01) + AT (0x40)
sign_cnt_hex="00000000"
aaguid_hex="00000000000000000000000000000000"  # 16 zero bytes
cred_id_hex=$(rand_hex 16)
cred_id_len_hex=$(printf '%04x' 16)

cose_key_hex=$(make_cose_key_hex "$X_HEX" "$Y_HEX")

auth_data_hex="${rp_hash_hex}${flags_hex}${sign_cnt_hex}${aaguid_hex}${cred_id_len_hex}${cred_id_hex}${cose_key_hex}"

# Build attestationObject CBOR: {"fmt":"none","attStmt":{},"authData":<bstr>}
att_obj_hex=""
att_obj_hex+=$(cbor_map_start 3)
att_obj_hex+=$(cbor_tstr "fmt")
att_obj_hex+=$(cbor_tstr "none")
att_obj_hex+=$(cbor_tstr "attStmt")
att_obj_hex+=$(cbor_map_start 0)
att_obj_hex+=$(cbor_tstr "authData")
att_obj_hex+=$(cbor_bstr "$auth_data_hex")

attestation_b64url=$(printf '%s' "$att_obj_hex" | xxd -r -p | openssl base64 -A | tr -d '=' | tr '+/' '-_')

# clientDataJSON
origin="https://${rp}"
client_data_json=$(jq -nc --arg chal "$challenge" --arg origin "$origin" '{type:"webauthn.create", challenge:$chal, origin:$origin}')
client_data_b64url=$(printf '%s' "$client_data_json" | openssl base64 -A | tr -d '=' | tr '+/' '-_')

# Credential ID (rawId) is credentialId we generated above
raw_id_b64url=$(printf '%s' "$cred_id_hex" | xxd -r -p | openssl base64 -A | tr -d '=' | tr '+/' '-_')

# Output JSON
jq -n \
  --arg id "$raw_id_b64url" \
  --arg rawId "$raw_id_b64url" \
  --arg attObj "$attestation_b64url" \
  --arg cdj "$client_data_b64url" \
  --arg userId "$userid" \
  --arg userName "$username" \
  '{
    user: { id: $userId, name: $userName, displayName: $userName },
    responseDecoded: { id: $id, rawId: $rawId },
    response: { attestationObject: $attObj, clientDataJSON: $cdj }
  }'
