//go:build ignore

package ignored

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bytemare/opaque"
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

// -- Setup

func GetServer() *opaque.Server {
	conf := opaque.DefaultConfiguration()

	server, err := conf.Server()
	if err != nil {
		log.Fatalln("OPAQUE server instantiation failed:", err)
	}

	err = server.SetKeyMaterial(
		user_auth_global_config.OpaqueServerId(),
		user_auth_global_config.OpaqueServerPrivateKey(),
		user_auth_global_config.OpaqueServerPublicKey(),
		user_auth_global_config.OpaqueServerSecretOprfSeed(),
	)
	if err != nil {
		log.Fatalln("OPAQUE server key material error:", err)
	}

	fmt.Println("OPAQUE server initialized.")
	return server
}

// -- Registration

func CreateRegistrationResponse(
	registrationRequestB64 string,
	userIdentifier string,
	server *opaque.Server,
	serverPublicKey []byte,
	secretOPRFSeed []byte,
) (string, error) {
	reqBytes, err := base64.RawURLEncoding.DecodeString(registrationRequestB64)
	if err != nil {
		return "", errors.New("base64 decoding failed: " + err.Error())
	}

	request, err := server.Deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		return "", errors.New("invalid registrationRequest: " + err.Error())
	}

	pubKey, err := server.Deserialize.DecodeAkePublicKey(serverPublicKey)
	if err != nil {
		return "", errors.New("invalid server AKE public key: " + err.Error())
	}

	response := server.RegistrationResponse(request, pubKey, []byte(userIdentifier), secretOPRFSeed)
	return base64.RawURLEncoding.EncodeToString(response.Serialize()), nil
}

func FinishRegistration(
	registrationRecordB64 string,
	userIdentifier string,
	server *opaque.Server,
) (*opaque.ClientRecord, error) {
	recordBytes, err := base64.RawURLEncoding.DecodeString(registrationRecordB64)
	if err != nil {
		return nil, errors.New("invalid base64 in registrationRecord: " + err.Error())
	}

	record, err := server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		return nil, errors.New("failed to deserialize registrationRecord: " + err.Error())
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(userIdentifier),
		ClientIdentity:       []byte(userIdentifier),
		RegistrationRecord:   record,
	}
	return clientRecord, nil
}

// -- Login

func StartLogin(
	startLoginRequestB64 string,
	clientRecord *opaque.ClientRecord,
	server *opaque.Server,
) (loginResponseB64 string, err error) {
	reqBytes, err := base64.RawURLEncoding.DecodeString(startLoginRequestB64)
	if err != nil {
		return "", errors.New("failed to decode startLoginRequest: " + err.Error())
	}

	ke1, err := server.Deserialize.KE1(reqBytes)
	if err != nil {
		return "", errors.New("failed to parse KE1: " + err.Error())
	}

	ke2, err := server.LoginInit(ke1, clientRecord)
	if err != nil {
		return "", errors.New("LoginInit failed: " + err.Error())
	}

	return base64.RawURLEncoding.EncodeToString(ke2.Serialize()), nil
}

func FinishLogin(
	finishLoginRequestB64 string,
	server *opaque.Server,
) (sessionKeyB64 string, err error) {
	ke3Bytes, err := base64.RawURLEncoding.DecodeString(finishLoginRequestB64)
	if err != nil {
		return "", errors.New("failed to decode finishLoginRequest: " + err.Error())
	}

	ke3, err := server.Deserialize.KE3(ke3Bytes)
	if err != nil {
		return "", errors.New("failed to parse KE3: " + err.Error())
	}

	if err := server.LoginFinish(ke3); err != nil {
		return "", errors.New("LoginFinish failed: " + err.Error())
	}

	sessionKey := server.SessionKey()
	return base64.RawURLEncoding.EncodeToString(sessionKey), nil
}

// -- Debug Utility (optional)

func VerifySessionKeysMatch(clientKeyB64 string, serverKey []byte) error {
	clientKey, err := base64.RawURLEncoding.DecodeString(clientKeyB64)
	if err != nil {
		return errors.New("invalid base64 session key from client: " + err.Error())
	}
	if !bytes.Equal(clientKey, serverKey) {
		return errors.New("session key mismatch")
	}
	return nil
}

func readInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func TestDriver() {
	server := GetServer()

	userIdentifier := "test-user@example.com" // must stay consistent across registration/login
	serverPublicKey := user_auth_global_config.OpaqueServerPublicKey()
	serverOprfSeed := user_auth_global_config.OpaqueServerSecretOprfSeed()

	// Step 1: Registration — receive registrationRequest
	regReq := readInput("Paste `registrationRequest` from RN client: ")

	// Step 2: Generate registrationResponse
	regResp, err := CreateRegistrationResponse(regReq, userIdentifier, server, serverPublicKey, serverOprfSeed)
	if err != nil {
		log.Fatalln("❌ Failed to create registration response:", err)
	}
	fmt.Println("✅ registrationResponse (send to RN client):")
	fmt.Println(regResp)

	// Step 3: Receive registrationRecord
	regRecord := readInput("Paste `registrationRecord` from RN client: ")

	clientRecord, err := FinishRegistration(regRecord, userIdentifier, server)
	if err != nil {
		log.Fatalln("❌ Failed to finish registration:", err)
	}
	fmt.Println("✅ Registration complete.\n")

	// Step 4: Login — receive startLoginRequest
	startLogin := readInput("Paste `startLoginRequest` from RN client: ")

	loginResp, err := StartLogin(startLogin, clientRecord, server)
	if err != nil {
		log.Fatalln("❌ Failed to start login:", err)
	}
	fmt.Println("✅ loginResponse (send to RN client):")
	fmt.Println(loginResp)

	// Step 5: Receive finishLoginRequest
	finishLogin := readInput("Paste `finishLoginRequest` from RN client: ")

	sessionKey, err := FinishLogin(finishLogin, server)
	if err != nil {
		log.Fatalln("❌ Failed to finish login:", err)
	}

	fmt.Println("✅ Login complete. Derived sessionKey:")
	fmt.Println(sessionKey)
}
