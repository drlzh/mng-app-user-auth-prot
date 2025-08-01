//go:build ignore

package ignored

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
)

func isSameConf(a, b *opaque.Configuration) bool {
	if a.OPRF != b.OPRF ||
		a.KDF != b.KDF ||
		a.MAC != b.MAC ||
		a.Hash != b.Hash ||
		a.KSF != b.KSF ||
		a.AKE != b.AKE {
		return false
	}

	return bytes.Equal(a.Context, b.Context)
}

func main() {
	// You can compose your own configuration or choose a recommended default configuration.
	// The two following configuration setups are the same.
	defaultConf := opaque.DefaultConfiguration()

	customConf := &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		KSF:     ksf.Argon2id,
		AKE:     opaque.RistrettoSha512,
		Context: nil,
	}

	if !isSameConf(defaultConf, customConf) {
		// isSameConf() this is just a demo function to check equality.
		log.Fatalln("Oh no! Configurations differ!")
	}

	// A configuration can be saved encoded and saved, and later loaded and decoded at runtime.
	// Any additional 'Context' is also included.
	encoded := defaultConf.Serialize()
	fmt.Printf("Encoded Configuration: %s\n", hex.EncodeToString(encoded))

	// This how you decode that configuration.
	conf, err := opaque.DeserializeConfiguration(encoded)
	if err != nil {
		log.Fatalf("Oh no! Decoding the configurations failed! %v", err)
	}

	if !isSameConf(defaultConf, conf) {
		log.Fatalln("Oh no! Something went wrong in decoding the configuration!")
	}

	fmt.Println("OPAQUE configuration is easy!")

}
