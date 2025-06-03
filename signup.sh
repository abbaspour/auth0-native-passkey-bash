#!/usr/bin/env bash

##########################################################################################
# Author: Amin Abbaspour
# Date: 2024-12-02
# License: LGPL 2.1 (https://github.com/abbaspour/auth0-native-passkey-bash/blob/master/LICENSE)
##########################################################################################

set -ueo pipefail

DIR=$(dirname "${BASH_SOURCE[0]}")
readonly DIR

function usage() {
  cat <<END >&2
USAGE: $0 [-e env] [-t tenant] [-d domain] [-c client_id] [-x client_secret] [-r realm] [-u username] [-v|-h]
        -e file        # .env file location (default cwd)
        -t tenant      # Auth0 tenant@region
        -d domain      # Auth0 custom domain
        -c client_id   # Auth0 client ID
        -x secret      # Auth0 client secret
        -r realm       # Auth0 database connection name, should be passkey enabled
        -u username    # user identifier (email, phone_number, username)
        -k file        # private key file
        -h|?           # usage
        -v             # verbose

eg,
     $0 -t abbaspour@us -c xxxx -r realm -u me@there.com
END
  exit $1
}

declare AUTH0_DOMAIN=''
declare CLIENT_ID=''
declare AUTH0_CLIENT_SECRET=''
declare REALM=''
declare EMAIL=''
declare PRIVATE_KEY_FILE="private-key.pem"

[[ -f "${DIR}/.env" ]] && . "${DIR}/.env"

while getopts "e:t:d:c:r:u:k:hv?" opt; do
  case ${opt} in
  e) source "${OPTARG}" ;;
  t) AUTH0_DOMAIN=$(echo ${OPTARG}.auth0.com | tr '@' '.') ;;
  d) AUTH0_DOMAIN=${OPTARG} ;;
  c) CLIENT_ID=${OPTARG} ;;
  r) REALM=${OPTARG} ;;
  u) EMAIL=${OPTARG} ;;
  k) PRIVATE_KEY_FILE=${OPTARG} ;;
  v) set -x ;;
  h | ?) usage 0 ;;
  *) usage 1 ;;
  esac
done

[[ -z "${AUTH0_DOMAIN}" ]] && { echo >&2 "ERROR: AUTH0_DOMAIN undefined"; usage 1; }
[[ -z "${CLIENT_ID}" ]] && { echo >&2 "ERROR: CLIENT_ID undefined"; usage 1; }
[[ -z "${REALM}" ]] && { echo >&2 "ERROR: REALM undefined"; usage 1; }
[[ -z "${EMAIL}" ]] && { echo >&2 "ERROR: username undefined"; usage 1; }

if [[ ! -f $PRIVATE_KEY_FILE ]]; then
    echo "Private key not found! Run the bootstrap script first."
    exit 1
fi

SIGNUP_RESPONSE=$(curl -s -X POST "https://$AUTH0_DOMAIN/passkey/register" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "'"$CLIENT_ID"'",
        "realm": "'"$REALM"'",
        "user_profile": {
            "email": "'"$EMAIL"'"
        }
    }')

register_error=$(echo "$SIGNUP_RESPONSE" | jq -r '.error // empty')
if [[ -n "${register_error}" ]]; then
  echo >&2 "ERROR: passkey register error: ${SIGNUP_RESPONSE}"
  exit 1
fi

[[ ! -d "${DIR}/.store" ]] && mkdir -p "${DIR}/.store"

declare STORE="./.store/${EMAIL}.json"
if [[ -f $STORE ]]; then
    echo "WARNING: store already exists at $STORE"
    #exit 1
fi

CHALLENGE=$(echo "$SIGNUP_RESPONSE" | jq -r '.authn_params_public_key.challenge // empty')
SESSION_ID=$(echo "$SIGNUP_RESPONSE" | jq -r '.auth_session // empty')
USER_ID=$(echo "$SIGNUP_RESPONSE" | jq -r '.authn_params_public_key.user.id // empty')

if [[ -z "$CHALLENGE" || -z "$SESSION_ID" ]]; then
    echo "Failed to obtain challenge and session ID. Response: $SIGNUP_RESPONSE"
    exit 1
fi

echo "Signup challenge obtained. Challenge: $CHALLENGE, Session ID: $SESSION_ID"

go run attestation.go --rp "${AUTH0_DOMAIN}" --challenge "${CHALLENGE}" --username "${EMAIL}" --userid "${USER_ID}" --key "${PRIVATE_KEY_FILE}" > "${STORE}"

ATTESTATION_OBJECT=$(jq -r .response.attestationObject "${STORE}")
CLIENT_DATA_JSON=$(jq -r .response.clientDataJSON "${STORE}")
CREDENTIAL_ID=$(jq -r .responseDecoded.rawId "${STORE}")

AUTH_RESPONSE=$(curl -s -X POST "https://$AUTH0_DOMAIN/oauth/token" \
    -H "Content-Type: application/json" \
    -d '{
        "grant_type": "urn:okta:params:oauth:grant-type:webauthn",
        "client_id": "'"$CLIENT_ID"'",
        "realm": "'"$REALM"'",
        "scope": "openid profile email",
        "auth_session": "'"$SESSION_ID"'",
        "authn_response": {
            "id": "'"$CREDENTIAL_ID"'",
            "rawId": "'"$CREDENTIAL_ID"'",
            "clientExtensionResults": {},
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "attestationObject": "'"$ATTESTATION_OBJECT"'",
                "clientDataJSON": "'"$CLIENT_DATA_JSON"'"
            }
        }
    }')

ID_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.id_token // empty')
readonly ID_TOKEN

if [[ -z "$ID_TOKEN" ]]; then
    echo "Authentication failed. Response: $AUTH_RESPONSE"
    exit 1
fi

echo "Authentication successful. ID Token: $ID_TOKEN"

jq -Rr 'split(".") | .[1] | @base64d | fromjson' <<< "${ID_TOKEN}"
