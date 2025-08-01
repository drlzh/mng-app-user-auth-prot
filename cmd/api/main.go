package main

import (
	"fmt"
	"github.com/bytemare/opaque"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/rsa/rsa_api"
	"log"
)

func printByteArray(b []byte) {
	for i := 0; i < len(b); i++ {
		if i%8 == 0 {
			fmt.Print("\t")
		}
		fmt.Printf("0x%02X", b[i])
		if i < len(b)-1 {
			fmt.Print(", ")
		}
		if i%8 == 7 {
			fmt.Println()
		}
	}
	if len(b)%8 != 0 {
		fmt.Println()
	}
}

func generateEd448Keypair() {
	priv, pub, err := ed448_api.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Println("const RootPrivateKey = ed448.PrivateKey{")
	printByteArray(priv[:])
	fmt.Println("}\n")

	fmt.Println("const RootPublicKey = ed448.PublicKey{")
	printByteArray(pub[:])
	fmt.Println("}")
}

func generateServerOpaqueKeypair() {

	serverID := []byte("mng-app-user-auth-prot-server")
	conf := opaque.DefaultConfiguration()
	secretOprfSeed := conf.GenerateOPRFSeed()
	serverPrivateKey, serverPublicKey := conf.KeyGen()

	if serverPrivateKey == nil || serverPublicKey == nil || secretOprfSeed == nil {
		log.Fatalf("Oh no! Something went wrong setting up the server secrets!")
	}

	fmt.Println("serverID = {")
	printByteArray(serverID[:])
	fmt.Println("}\n")

	fmt.Println("serverPrivateKey = {")
	printByteArray(serverPrivateKey[:])
	fmt.Println("}\n")

	fmt.Println("serverPublicKey = {")
	printByteArray(serverPublicKey[:])
	fmt.Println("}\n")

	fmt.Println("secretOprfSeed = {")
	printByteArray(secretOprfSeed[:])
	fmt.Println("}\n")

}

func generateRsaKeypair() {
	privPEM, pubPEM, err := rsa_api.GenerateKeyPair()
	if err != nil {
		log.Fatalf("RSA key generation failed: %v", err)
	}

	fmt.Println("const RootRSAPrivateKey = []byte{")
	printByteArray(privPEM)
	fmt.Println("}\n")

	fmt.Println("const RootRSAPublicKey = []byte{")
	printByteArray(pubPEM)
	fmt.Println("}")
}

func main() {

	//chacha_poly1305_api.RunningCompetition()
	//ed448_api.InteractiveTestDriver()
	//ecdh256_api.TestDriver()
	generateEd448Keypair()
	//generateRsaKeypair()
	//generateServerOpaqueKeypair()
	//hashcash_api.TestDriver()
	//opaque_api.TestDriver()
	//poly1305_api.TestDriver()
	//chacha_api.TestDriver()
	//chacha_poly1305_api.TestDriver()
	//rsa_api.TestDriver()
	//ed448_api.TestDriver()
	//ghetto_db.TestDriver()

}
