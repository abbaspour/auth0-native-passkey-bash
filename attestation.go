package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/webauthn"
	_ "github.com/fxamacker/webauthn/packed"
)

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type WebauthnAttestation struct {
	User      *webauthn.User
	Challenge []byte
	Options   string
}

type FullClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}
type WebauthnResponse struct {
	Id       string `json:"id"`
	RawId    string `json:"rawId"`
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	}
}

type ECDSASignature struct {
	R, S *big.Int
}

type attestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}
type attestationStatementClean struct {
	Algorithm int    `json:"alg"`
	Signature string `json:"sig"`
	R         string `json:"r"`
	S         string `json:"s"`
}
type attestationObject struct {
	Format    string               `json:"fmt"`
	Statement attestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type FullAttestationObject struct {
	Raw64     string                    `json:"raw64"`
	Format    string                    `json:"fmt"`
	Statement attestationStatementClean `json:"attStmt"`
	AuthData  AuthDataDecoded           `json:"authData"`
}

type WebauthnResponseComplete struct {
	Id                string `json:"id"`
	RawId             string `json:"rawId"`
	AttestationObject FullAttestationObject
	ClientDataJSON    FullClientData
}

type WebAuthnResponseRaw struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthData          string `json:"authData"`
}

type WebAuthnRegister struct {
	WebauthnUser             User                                `json:"user"`
	WebauthnConfig           webauthn.Config                     `json:"config"`
	WebauthnOptions          *virtualwebauthn.AttestationOptions `json:"options"`
	WebauthnResponseComplete WebauthnResponseComplete            `json:"responseDecoded"`
	WebAuthnResponseRaw      WebAuthnResponseRaw                 `json:"response"`
}

type AuthDataDecoded struct {
	RpIdHash            string `json:"rpIdHash"`
	Flags               string `json:"flags"`
	SignCount           string `json:"signCount"`
	Aaguid              string `json:"aaguid"`
	CredentialIdLength  uint16 `json:"credentialIdLength"`
	CredentialId        string `json:"credentialId"`
	CredentialPublicKey string `json:"credentialPublicKey"`
	PubKeyX             string `json:"pubKeyX"`
	PubKeyY             string `json:"pubKeyY"`
}

func register(webauthnConfig webauthn.Config, challenge []byte, username string, userId string, keyData []byte, keyType virtualwebauthn.KeyType) (*virtualwebauthn.AttestationOptions, string) {
	cred := virtualwebauthn.NewCredentialWithImportedKey(keyType, keyData)

	rp := virtualwebauthn.RelyingParty{Name: webauthnConfig.RPName, ID: webauthnConfig.RPID, Origin: "https://" + webauthnConfig.RPID}

	// A mock authenticator that represents a security key or biometrics module
	authenticator := virtualwebauthn.NewAuthenticator()

	attestation := startWebauthnRegister(webauthnConfig, challenge, username, userId)

	attestationOptions := createAttestationOptions(attestation)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	verifyWebauthnRegister(webauthnConfig, attestation, attestationResponse)

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte( /*attestationOptions.UserID*/ userId)

	// Add the EC2 credential to the mock authenticator
	authenticator.AddCredential(cred)

	return attestationOptions, attestationResponse
}

func createAttestationOptions(attestation *WebauthnAttestation) *virtualwebauthn.AttestationOptions {
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	if err != nil {
		panic(fmt.Sprintf("Error generation attestation options: %v", err))
	}

	return attestationOptions
}

// starts a webauthn registration by creating a new user and generating an attestation challenge
func startWebauthnRegister(webauthnConfig webauthn.Config, challenge []byte, username string, userId string) *WebauthnAttestation {
	// Create a new user for the webauthn registration
	user := newWebauthnUser(username, userId)

	if len(challenge) > 0 {
		webauthnConfig.ChallengeLength = len(challenge)
	}

	options, _ := webauthn.NewAttestationOptions(&webauthnConfig, user)

	// If a challenge flag was provided, set it in the options
	if len(challenge) > 0 {
		options.Challenge = challenge
	}

	//options.User.ID = userId

	// Marshal the options to JSON for storage
	optionsJSON, _ := json.Marshal(options)
	return &WebauthnAttestation{User: user, Challenge: options.Challenge, Options: string(optionsJSON)}
}

// simulates the final step of a webauthn registration by verifying the attestation to ensure it's valid
func verifyWebauthnRegister(webauthnConfig webauthn.Config, attestation *WebauthnAttestation, response string) *webauthn.Credential {
	// Parse the attestation response
	parsedAttestation, _ := webauthn.ParseAttestation(strings.NewReader(response))

	// Verify the attestation to ensure it's valid
	_, _, _ = webauthn.VerifyAttestation(parsedAttestation, &webauthn.AttestationExpectedData{
		Origin:           "https://" + webauthnConfig.RPID,
		RPID:             webauthnConfig.RPID,
		CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
		Challenge:        base64.RawURLEncoding.EncodeToString(attestation.Challenge),
		UserVerification: webauthn.UserVerificationPreferred,
	})

	return parsedAttestation.AuthnData.Credential
}

// creates a new webauthn.User object with automated test user's data
func newWebauthnUser(username string, userId string) *webauthn.User {
	// Get the current time in an european human-readable format
	currentTime := time.Now().Format("02/01/2006 15:04:05")

	// If a username was provided, use it, otherwise use the default values
	user := &webauthn.User{
		//ID:          userId,
		ID:          []byte(userId),
		Name:        username,
		DisplayName: fmt.Sprintf("%s -- %s", username, currentTime),
	}

	return user
}

func MarshalJSON(value any, pretty string) []byte {
	// If the pretty flag is set, pretty print the JSON
	if len(pretty) > 0 {
		valueJSON, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			panic(fmt.Sprintf("Error marshalling attestation options: %v", err))
		}
		return valueJSON
	}

	// Otherwise, compact print the JSON
	valueJSON, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("Error marshalling attestation options: %v", err))
	}
	return valueJSON
}

func encodeToHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func decodeAuthData(authData []byte) AuthDataDecoded {
	// Ensure authData is at least 37 bytes
	if len(authData) < 37 {
		panic("authData is too short")
	}

	// Parse rpIdHash
	rpIdHash := authData[:32]

	// Parse flags
	flags := authData[32]

	// Parse signCount
	signCount := authData[33:37]

	// Offset where attestedCredentialData starts
	offset := 37

	// AAGUID is the next 16 bytes
	aaguid := authData[offset : offset+16]
	offset += 16

	// credentialIdLength is the next 2 bytes
	credentialIdLength := binary.BigEndian.Uint16(authData[offset : offset+2])
	offset += 2

	// credentialId is the next credentialIdLength bytes
	credentialId := authData[offset : offset+int(credentialIdLength)]
	offset += int(credentialIdLength)

	// The remaining bytes are for credentialPublicKey which is COSE-encoded.
	// Its parsing is more involved and depends on your needs.
	credentialPublicKey := authData[offset:]

	// Decode the credentialPublicKey
	var coseMap map[int]interface{}
	if err := cbor.Unmarshal(credentialPublicKey, &coseMap); err != nil {
		panic(err)
	}

	// Extract the x and y coordinates of the public key and convert them to big.Int
	// The publicKey variable is CBOR-encoded (not regular PEM string), which after decoding it in publicKeyObject should give an output like this:
	//		 1: 2,              -> Ellipic Curve key type
	//		 3: -7,             -> ES256 signature algorithm
	//		-1: 1,              -> P-256 curve
	//		-2: 0x7885DB484..., -> X value
	//		-3: 0x814F3DD31...  -> Y value
	xBytes := coseMap[-2].([]byte)
	yBytes := coseMap[-3].([]byte)

	return AuthDataDecoded{
		RpIdHash:            encodeToHex(rpIdHash),
		Flags:               fmt.Sprintf("%08b", flags),
		SignCount:           encodeToHex(signCount),
		Aaguid:              encodeToHex(aaguid),
		CredentialIdLength:  credentialIdLength,
		CredentialId:        encodeToHex(credentialId),
		CredentialPublicKey: encodeToHex(credentialPublicKey),
		PubKeyX:             encodeToHex(xBytes),
		PubKeyY:             encodeToHex(yBytes),
	}
}

// ParsePrivateKey reads a key file, parses it, and returns the private key in PKCS#8 []byte format,
// the type of the key (RSA or EC), and any error encountered.
func ParsePrivateKey(keyFileName string) ([]byte, virtualwebauthn.KeyType, error) {
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
	rp := flag.String("rp", "", "Relying Party (RP) domain name.")
	challengeStr := flag.String("challenge", "", "Optional. Hex value only. If not provided, a random challenge will be generated.")
	username := flag.String("username", "", "Username for the webauthn registration.")
	userIdStr := flag.String("userid", "", "userID for the webauthn registration.")
	pretty := "true"
	keyPath := flag.String("key", "", "Private key filename.")

	flag.Parse()

	privateKeyBytes, keyType, err := ParsePrivateKey(*keyPath)
	if err != nil {
		panic(err)
	}

	//challenge := []byte(*challengeStr)
	challenge, err := base64.RawURLEncoding.DecodeString(*challengeStr)
	if err != nil {
		panic(err)
	}

	var webauthnConfig = webauthn.Config{
		RPID:                    *rp,
		RPName:                  *rp,
		Timeout:                 uint64(60000),
		ChallengeLength:         64,
		UserVerification:        webauthn.UserVerificationRequired,
		Attestation:             webauthn.AttestationNone,
		CredentialAlgs:          []int{webauthn.COSEAlgES256},
		AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
	}

	// Run a webauthn attestation flow
	attestationOptions, attestationResponse := register(webauthnConfig, challenge, *username, *userIdStr, privateKeyBytes, keyType)

	// Unmarshal the webauthn response to get the attestation object and clientDataJSON
	var WebauthnResponse WebauthnResponse
	json.Unmarshal([]byte(attestationResponse), &WebauthnResponse)

	// Decode the clientDataJSON from Base64
	decodedClientDataBytes, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Response.ClientDataJSON)
	if err != nil {
		panic(err)
	}
	// Now unmarshal the JSON bytes into the struct
	var clientData FullClientData
	err = json.Unmarshal(decodedClientDataBytes, &clientData)
	if err != nil {
		panic(err)
	}

	// Decode the Base64URL string to bytes then encode to hex
	decodedBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		fmt.Println("Error decoding base64URL:", err)
		return
	}
	clientData.Challenge = encodeToHex(decodedBytes)

	// Decode the attestationObject from Base64
	decodedAttestationObjectBytes, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Response.AttestationObject)
	if err != nil {
		panic(err)
	}

	// The data structure to decode into
	var result attestationObject
	err = cbor.Unmarshal(decodedAttestationObjectBytes, &result)
	if err != nil {
		panic(err)
	}

	// Decode the WebauthnResponse.Id from Base64
	WebauthnResponseIdByte, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Id)
	if err != nil {
		log.Fatalf("error decoding base64 string: %v", err)
	}

	// Decode the authData
	decodedAuthData := decodeAuthData(result.AuthData)

	// Extract r and s from the DER-encoded signature
	var sig ECDSASignature
	asn1.Unmarshal(result.Statement.Signature, &sig)

	// Create the WebAuthnRegister struct to hold all the data
	webauthnRegister := WebAuthnRegister{
		User{
			ID:          attestationOptions.UserID,
			Name:        attestationOptions.UserName,
			DisplayName: attestationOptions.UserDisplayName,
		},
		webauthnConfig,
		attestationOptions,
		WebauthnResponseComplete{
			Id:    base64.RawURLEncoding.EncodeToString(WebauthnResponseIdByte),
			RawId: WebauthnResponse.RawId,
			AttestationObject: FullAttestationObject{
				Format: result.Format,
				Statement: attestationStatementClean{
					Algorithm: result.Statement.Algorithm,
					Signature: base64.RawURLEncoding.EncodeToString(result.Statement.Signature),
					R:         "0x" + sig.R.Text(16),
					S:         "0x" + sig.S.Text(16),
				},
				AuthData: decodedAuthData,
			},
			ClientDataJSON: clientData,
		},
		WebAuthnResponseRaw{
			AttestationObject: base64.RawURLEncoding.EncodeToString(decodedAttestationObjectBytes),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(decodedClientDataBytes),
			AuthData:          base64.RawURLEncoding.EncodeToString(result.AuthData),
		},
	}

	// Output the data in JSON format
	webAuthnRegisterDataJSON := MarshalJSON(webauthnRegister, pretty)
	fmt.Print(string(webAuthnRegisterDataJSON))
}
