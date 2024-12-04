#!/bin/bash

# Generate a private key using OpenSSL and save it to a file
PRIVATE_KEY_FILE="private-key.pem"

if [[ -f $PRIVATE_KEY_FILE ]]; then
    echo "Private key already exists at $PRIVATE_KEY_FILE"
else
    openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
    echo "Private key generated and saved to $PRIVATE_KEY_FILE"
fi
