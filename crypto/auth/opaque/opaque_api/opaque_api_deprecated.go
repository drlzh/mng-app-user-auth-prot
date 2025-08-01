//go:build ignore

package opaque_api

import (
	"encoding/base64"
	"errors"
	"fmt"
	opaque_store2 "github.com/drlzh/mng-app-user-auth-prot/opaque_store"
	"log"

	"github.com/bytemare/opaque"
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

type DefaultOpaqueService struct {
	store opaque_store2.OpaqueClientStore
}

func NewDefaultOpaqueService(s opaque_store2.OpaqueClientStore) *DefaultOpaqueService {
	return &DefaultOpaqueService{store: s}
}

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

	return server
}

// RegistrationStep1 receives registrationRequest and returns registrationResponse.
func RegistrationStep1(
	userIdentifier, registrationRequestB64 string,
) (string, error) {
	reqBytes, err := base64.RawURLEncoding.DecodeString(registrationRequestB64)
	if err != nil {
		return "", errors.New("invalid base64 registrationRequest: " + err.Error())
	}

	server := GetServer()
	serverPub := user_auth_global_config.OpaqueServerPublicKey()
	oprfSeed := user_auth_global_config.OpaqueServerSecretOprfSeed()

	request, err := server.Deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		return "", errors.New("invalid registration request: " + err.Error())
	}
	pubKey, err := server.Deserialize.DecodeAkePublicKey(serverPub)
	if err != nil {
		return "", errors.New("invalid server public key: " + err.Error())
	}

	response := server.RegistrationResponse(request, pubKey, []byte(userIdentifier), oprfSeed)
	return base64.RawURLEncoding.EncodeToString(response.Serialize()), nil
}

// registrationStore handles internal saving of user registration.
// If allowOverwrite is false, it fails if user already exists.
func (store *DefaultOpaqueService) registrationStore(
	userIdentifier string,
	registrationRecordB64 string,
	allowOverwrite bool,
) error {
	exists, err := store.Exists(userIdentifier)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists && !allowOverwrite {
		return errors.New("user already registered")
	}

	recordBytes, err := base64.RawURLEncoding.DecodeString(registrationRecordB64)
	if err != nil {
		return errors.New("invalid base64 registrationRecord: " + err.Error())
	}

	server := GetServer()
	record, err := server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		return errors.New("invalid registration record: " + err.Error())
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(userIdentifier),
		ClientIdentity:       []byte(userIdentifier),
		RegistrationRecord:   record,
	}

	serialized := clientRecord.RegistrationRecord.Serialize()
	return store.Save(userIdentifier, serialized)
}

// RegistrationStep2 receives registrationRecord and saves the user.
func RegistrationStep2(
	store *opaque_store2.GhettoAdapter,
	userIdentifier, registrationRecordB64 string,
) error {
	return registrationStore(store, userIdentifier, registrationRecordB64, false)
}

// LoginStep1 receives startLoginRequest and returns loginResponse and serialized server state.
func LoginStep1(
	store *opaque_store2.GhettoAdapter,
	userIdentifier, startLoginRequestB64 string,
) (loginResponseB64, serverStateB64 string, err error) {
	startBytes, err := base64.RawURLEncoding.DecodeString(startLoginRequestB64)
	if err != nil {
		return "", "", errors.New("invalid base64 startLoginRequest: " + err.Error())
	}

	server := GetServer()

	// Load client record
	recordBytes, err := store.Load(userIdentifier)
	if err != nil {
		return "", "", fmt.Errorf("failed to load user record: %w", err)
	}

	record, err := server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to deserialize record: %w", err)
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(userIdentifier),
		ClientIdentity:       []byte(userIdentifier),
		RegistrationRecord:   record,
	}

	ke1, err := server.Deserialize.KE1(startBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse KE1: %w", err)
	}

	ke2, err := server.LoginInit(ke1, clientRecord)
	if err != nil {
		return "", "", fmt.Errorf("LoginInit failed: %w", err)
	}

	loginResponseB64 = base64.RawURLEncoding.EncodeToString(ke2.Serialize())
	serverStateB64 = base64.RawURLEncoding.EncodeToString(server.SerializeState())
	return loginResponseB64, serverStateB64, nil
}

// LoginStep2 receives finishLoginRequest and previous serverState, and returns the sessionKey.
func LoginStep2(
	finishLoginRequestB64, serverStateB64 string,
) (string, error) {
	ke3Bytes, err := base64.RawURLEncoding.DecodeString(finishLoginRequestB64)
	if err != nil {
		return "", errors.New("invalid base64 finishLoginRequest: " + err.Error())
	}

	stateBytes, err := base64.RawURLEncoding.DecodeString(serverStateB64)
	if err != nil {
		return "", errors.New("invalid base64 serverState: " + err.Error())
	}

	server := GetServer()
	err = server.SetAKEState(stateBytes)
	if err != nil {
		return "", fmt.Errorf("SetAKEState failed: %w", err)
	}

	ke3, err := server.Deserialize.KE3(ke3Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to deserialize KE3: %w", err)
	}

	if err := server.LoginFinish(ke3); err != nil {
		return "", fmt.Errorf("LoginFinish failed: %w", err)
	}

	sessionKey := server.SessionKey()
	return base64.RawURLEncoding.EncodeToString(sessionKey), nil
}

// PasswordResetStep1: identical to RegistrationStep1 — client starts a new registration
func PasswordResetStep1(
	userIdentifier, registrationRequestB64 string,
) (string, error) {
	// Reuse RegistrationStep1
	return RegistrationStep1(userIdentifier, registrationRequestB64)
}

// PasswordResetStep2: overwrites the user’s previous record
func PasswordResetStep2(
	store *opaque_store2.GhettoAdapter,
	userIdentifier, registrationRecordB64 string,
) error {
	return registrationStore(store, userIdentifier, registrationRecordB64, true)
}
