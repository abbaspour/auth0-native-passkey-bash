package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/descope/virtualwebauthn"
	"github.com/fxamacker/webauthn"
	"os"
	"time"
)

type WebauthnAssertion struct {
	User         *webauthn.User
	CredentialID []byte
	Challenge    []byte
	Options      string
}

func login(challenge []byte, username string, userId []byte, rpId string, keyData []byte, keyType virtualwebauthn.KeyType, credID string) (*virtualwebauthn.AssertionOptions, string) {

	webOrigin := "https://" + rpId
	rpName := rpId

	// Create a virtual credential using the parsed RSA private key
	cred := virtualwebauthn.NewCredentialWithImportedKey(keyType, keyData)
	cred.ID = []byte(credID)

	// The relying party settings should mirror those on the actual WebAuthn server
	rp := virtualwebauthn.RelyingParty{Name: rpName, ID: rpId, Origin: webOrigin}

	// A mock authenticator that represents a security key or biometrics module
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(cred)

	authenticator.Options.UserHandle = userId

	//assertion := startWebauthnAssertion(challenge, username, userId, rpId, rpName)
	assertion := startWebauthnLogin(challenge, username, userId, rpId, cred.ID)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	if err != nil {
		panic(fmt.Sprintf("Error generation assertion options: %v", err))
	}

	foundCredential := authenticator.FindAllowedCredential(*assertionOptions)
	if !bytes.Equal(foundCredential.ID, cred.ID) {
		panic("Credential not found")
	}

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

	return assertionOptions, assertionResponse
}

func startWebauthnLogin(challenge []byte, username string, userId []byte, rpId string, credID []byte) *WebauthnAssertion {

	// Get the current time in a european human-readable format
	currentTime := time.Now().Format("02/01/2006 15:04:05")

	user := &webauthn.User{
		ID:          userId,
		Name:        username,
		DisplayName: fmt.Sprintf("%s -- %s", username, currentTime),
	}

	user.CredentialIDs = append(user.CredentialIDs, credID)

	var webauthnConfig = &webauthn.Config{
		RPID:                    rpId,
		RPName:                  rpId,
		Timeout:                 uint64(60000),
		ChallengeLength:         len(challenge),
		ResidentKey:             webauthn.ResidentKeyDiscouraged,
		UserVerification:        webauthn.UserVerificationDiscouraged,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
	}

	options, err := webauthn.NewAssertionOptions(webauthnConfig, user)
	if err != nil {
		panic(err)
	}

	options.Challenge = challenge

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		panic(err)
	}

	return &WebauthnAssertion{User: user, CredentialID: credID, Challenge: options.Challenge, Options: string(optionsJSON)}
}

// ParsePrivateKey reads a key file, parses it, and returns the private key in PKCS#8 []byte format,
// the type of the key (RSA or EC), and any error encountered.
func loginParsePrivateKey(keyFileName string) ([]byte, virtualwebauthn.KeyType, error) {
	// Read the private key file
	keyData, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key based on the type
	var parsedKey interface{}
	var keyType virtualwebauthn.KeyType
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8 format
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
	case "RSA PRIVATE KEY": // PKCS#1 format
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
		keyType = "RSA"
	case "EC PRIVATE KEY": // EC key in PEM format
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse EC private key: %w", err)
		}
		keyType = "EC"
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", block.Type)
	}

	// Detect key type if not already set
	switch parsedKey.(type) {
	case *rsa.PrivateKey:
		keyType = virtualwebauthn.KeyTypeRSA
	case *ecdsa.PrivateKey:
		keyType = virtualwebauthn.KeyTypeEC2
	default:
		return nil, "", fmt.Errorf("unknown key type")
	}

	// Marshal the private key into PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(parsedKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	return privateKeyBytes, keyType, nil
}

func main() {
	challengeStr := flag.String("challenge", "", "Optional. Hex value only. If not provided, a random challenge will be generated.")
	username := flag.String("username", "", "Optional. Username for the webauthn registration. If not provided, a default username will be used.")
	rp := flag.String("rp", "", "Relying Party (RP) domain name.")
	keyPath := flag.String("key", "", "Private key filename.")
	credID := flag.String("credId", "", "Credential ID.")
	userIdStr := flag.String("userid", "", "userID for the webauthn registration.")
	flag.Parse()

	privateKeyBytes, keyType, err := loginParsePrivateKey(*keyPath)
	if err != nil {
		panic(err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(*challengeStr)
	if err != nil {
		panic(err)
	}

	_, assertionResponse := login(challenge, *username, ([]byte)(*userIdStr), *rp, privateKeyBytes, keyType, *credID)

	fmt.Println(assertionResponse)
}
