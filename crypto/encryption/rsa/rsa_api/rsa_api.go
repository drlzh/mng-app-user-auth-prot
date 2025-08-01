package rsa_api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/sha3"
)

const DefaultKeyBits = 5 * 1024 // 5120 bits

type (
	PrivateKey = []byte // PEM-encoded PKCS#8
	PublicKey  = []byte // PEM-encoded PKIX
)

func GenerateKeyPair() (PrivateKey, PublicKey, error) {
	bits := DefaultKeyBits
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	return privPEM, pubPEM, nil
}

func Encrypt(pubPEM PublicKey, plaintext []byte, label []byte) ([]byte, error) {
	pub, err := parsePubKey(pubPEM)
	if err != nil {
		return nil, err
	}
	hash := sha3.New512()
	return rsa.EncryptOAEP(hash, rand.Reader, pub, plaintext, label)
}

func Decrypt(privPEM PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	priv, err := parsePrivKey(privPEM)
	if err != nil {
		return nil, err
	}
	hash := sha3.New512()
	return rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, label)
}

func parsePrivKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("rsa: invalid private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parsePubKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("rsa: invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("rsa: not an RSA public key")
	}
	return rsaPub, nil
}
