package opaque_api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/bytemare/opaque"
	"github.com/drlzh/mng-app-user-auth-prot/opaque_store"
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

// DefaultOpaqueService implements the OPAQUE authentication flow.
type DefaultOpaqueService struct {
	store opaque_store.OpaqueClientStore
}

// NewDefaultOpaqueService creates a new OPAQUE service instance with the given store.
func NewDefaultOpaqueService(s opaque_store.OpaqueClientStore) *DefaultOpaqueService {
	return &DefaultOpaqueService{store: s}
}

func (svc *DefaultOpaqueService) getServer() *opaque.Server {
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

func (svc *DefaultOpaqueService) RegistrationStep1(
	user user_auth_global_config.UniqueUser, registrationRequestB64 string,
) (string, error) {
	reqBytes, err := base64.RawURLEncoding.DecodeString(registrationRequestB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}

	server := svc.getServer()

	request, err := server.Deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		return "", fmt.Errorf("deserialization failed: %w", err)
	}

	pubKey, err := server.Deserialize.DecodeAkePublicKey(user_auth_global_config.OpaqueServerPublicKey())
	if err != nil {
		return "", fmt.Errorf("decode server public key failed: %w", err)
	}

	response := server.RegistrationResponse(
		request,
		pubKey,
		[]byte(user.String()),
		user_auth_global_config.OpaqueServerSecretOprfSeed(),
	)

	return base64.RawURLEncoding.EncodeToString(response.Serialize()), nil
}

func (svc *DefaultOpaqueService) RegistrationStep2(
	user user_auth_global_config.UniqueUser, registrationRecordB64 string,
) error {
	exists, err := svc.store.Exists(user)
	if err != nil {
		return fmt.Errorf("existence check failed: %w", err)
	}
	if exists {
		return errors.New("user already registered")
	}
	return svc.saveRecord(user, registrationRecordB64)
}

func (svc *DefaultOpaqueService) PasswordResetStep1(
	user user_auth_global_config.UniqueUser, registrationRequestB64 string,
) (string, error) {
	return svc.RegistrationStep1(user, registrationRequestB64)
}

func (svc *DefaultOpaqueService) PasswordResetStep2(
	user user_auth_global_config.UniqueUser, registrationRecordB64 string,
) error {
	return svc.saveRecord(user, registrationRecordB64)
}

func (svc *DefaultOpaqueService) LoginStep1(
	user user_auth_global_config.UniqueUser, startLoginRequestB64 string,
) (string, string, error) {
	startBytes, err := base64.RawURLEncoding.DecodeString(startLoginRequestB64)
	if err != nil {
		return "", "", fmt.Errorf("decode KE1: %w", err)
	}

	server := svc.getServer()

	recordBytes, err := svc.store.Load(user)
	if err != nil {
		return "", "", fmt.Errorf("load user record: %w", err)
	}

	record, err := server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		return "", "", fmt.Errorf("record deserialization failed: %w", err)
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(user.String()),
		ClientIdentity:       []byte(user.String()),
		RegistrationRecord:   record,
	}

	ke1, err := server.Deserialize.KE1(startBytes)
	if err != nil {
		return "", "", fmt.Errorf("KE1 parse error: %w", err)
	}

	ke2, err := server.LoginInit(ke1, clientRecord)
	if err != nil {
		return "", "", fmt.Errorf("LoginInit error: %w", err)
	}

	loginResponse := base64.RawURLEncoding.EncodeToString(ke2.Serialize())
	state := base64.RawURLEncoding.EncodeToString(server.SerializeState())
	return loginResponse, state, nil
}

func (svc *DefaultOpaqueService) LoginStep2(
	finishLoginRequestB64, serverStateB64 string,
) (string, error) {
	ke3Bytes, err := base64.RawURLEncoding.DecodeString(finishLoginRequestB64)
	if err != nil {
		return "", fmt.Errorf("decode KE3: %w", err)
	}

	stateBytes, err := base64.RawURLEncoding.DecodeString(serverStateB64)
	if err != nil {
		return "", fmt.Errorf("decode serverState: %w", err)
	}

	server := svc.getServer()
	if err := server.SetAKEState(stateBytes); err != nil {
		return "", fmt.Errorf("SetAKEState failed: %w", err)
	}

	ke3, err := server.Deserialize.KE3(ke3Bytes)
	if err != nil {
		return "", fmt.Errorf("deserialize KE3 failed: %w", err)
	}

	if err := server.LoginFinish(ke3); err != nil {
		return "", fmt.Errorf("LoginFinish failed: %w", err)
	}

	sessionKey := server.SessionKey()
	return base64.RawURLEncoding.EncodeToString(sessionKey), nil
}

func (svc *DefaultOpaqueService) saveRecord(
	user user_auth_global_config.UniqueUser, registrationRecordB64 string,
) error {
	recordBytes, err := base64.RawURLEncoding.DecodeString(registrationRecordB64)
	if err != nil {
		return fmt.Errorf("base64 decode error: %w", err)
	}

	server := svc.getServer()
	record, err := server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		return fmt.Errorf("record deserialization error: %w", err)
	}

	clientRecord := &opaque.ClientRecord{
		CredentialIdentifier: []byte(user.String()),
		ClientIdentity:       []byte(user.String()),
		RegistrationRecord:   record,
	}

	return svc.store.Save(user, clientRecord.RegistrationRecord.Serialize())
}
