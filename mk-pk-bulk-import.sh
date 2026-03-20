#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2026-03-19
# License: LGPL 2.1 (https://github.com/abbaspour/auth0-native-passkey-bash/blob/master/LICENSE)
##########################################################################################

set -ueo pipefail

DIR=$(dirname "${BASH_SOURCE[0]}")
readonly DIR

function usage() {
  cat <<END >&2
USAGE: $0 [-i email] [-o output-file] [-s store-dir] [-v|-h]
        -i email       # user email address (required)
        -o file        # output file (default: bulk-import/{email}.json)
        -s dir         # store directory (default: .store)
        -h|?           # usage
        -v             # verbose

eg,
     $0 -i user@example.com
     $0 -i user@example.com -o /tmp/import.json
END
  exit $1
}

declare EMAIL=''
declare OUTPUT_FILE=''
declare STORE_DIR="${DIR}/.store"

while getopts "i:o:s:hv?" opt; do
  case ${opt} in
  i) EMAIL=${OPTARG} ;;
  o) OUTPUT_FILE=${OPTARG} ;;
  s) STORE_DIR=${OPTARG} ;;
  v) set -x ;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${EMAIL}" ]] && { echo >&2 "ERROR: email undefined"; usage 1; }

STORE_FILE="${STORE_DIR}/${EMAIL}.json"
[[ -f "${STORE_FILE}" ]] || { echo >&2 "ERROR: store file not found: ${STORE_FILE}"; exit 1; }

[[ -z "${OUTPUT_FILE}" ]] && OUTPUT_FILE="${DIR}/bulk-import/${EMAIL}.json"

OUTPUT_DIR=$(dirname "${OUTPUT_FILE}")
[[ -d "${OUTPUT_DIR}" ]] || mkdir -p "${OUTPUT_DIR}"

# Convert hex (0x...) to base64url
hex_to_base64url() {
    local hex="${1#0x}"
    printf '%s' "${hex}" | xxd -r -p | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# Convert hex AAGUID (0x<32 hex chars>) to UUID string format
hex_to_uuid() {
    local hex="${1#0x}"
    printf '%s-%s-%s-%s-%s' \
        "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

# Extract fields from store
KEY_ID=$(jq -r '.responseDecoded.rawId' "${STORE_FILE}")
CRED_PUB_KEY_HEX=$(jq -r '.responseDecoded.AttestationObject.authData.credentialPublicKey' "${STORE_FILE}")
AAGUID_HEX=$(jq -r '.responseDecoded.AttestationObject.authData.aaguid' "${STORE_FILE}")
FLAGS=$(jq -r '.responseDecoded.AttestationObject.authData.flags' "${STORE_FILE}")
USER_HANDLE=$(jq -r '.user.id' "${STORE_FILE}")
RPID=$(jq -r '.config.RPID' "${STORE_FILE}")
ATTACHMENT=$(jq -r '.config.AuthenticatorAttachment' "${STORE_FILE}")

PUBLIC_KEY=$(hex_to_base64url "${CRED_PUB_KEY_HEX}")
AAGUID=$(hex_to_uuid "${AAGUID_HEX}")

# Flags byte stored as binary string MSB-first (bit7..bit0):
#   index 3 = bit 4 (BS - backup state)
#   index 4 = bit 3 (BE - backup eligible)
BE="${FLAGS:4:1}"
BS="${FLAGS:3:1}"

[[ "${BE}" == "1" ]] && DEVICE_TYPE="multi_device" || DEVICE_TYPE="single_device"
[[ "${BS}" == "1" ]] && BACKED_UP="true" || BACKED_UP="false"

# platform authenticators use the internal transport
if [[ "${ATTACHMENT}" == "platform" ]]; then
    TRANSPORTS='["internal"]'
else
    TRANSPORTS='["usb","nfc","ble","hybrid"]'
fi

jq -n \
    --arg email "${EMAIL}" \
    --arg key_id "${KEY_ID}" \
    --arg public_key "${PUBLIC_KEY}" \
    --arg user_handle "${USER_HANDLE}" \
    --arg relying_party_id "${RPID}" \
    --arg device_type "${DEVICE_TYPE}" \
    --arg aaguid "${AAGUID}" \
    --argjson transports "${TRANSPORTS}" \
    --argjson backed_up "${BACKED_UP}" \
    '[{
        "email": $email,
        "passkeys": [{
            "key_id": $key_id,
            "public_key": $public_key,
            "user_handle": $user_handle,
            "relying_party_id": $relying_party_id,
            "credential_device_type": $device_type,
            "aaguid": $aaguid,
            "transports": $transports,
            "credential_backed_up": $backed_up
        }]
    }]' > "${OUTPUT_FILE}"

echo "Bulk import file created: ${OUTPUT_FILE}"
