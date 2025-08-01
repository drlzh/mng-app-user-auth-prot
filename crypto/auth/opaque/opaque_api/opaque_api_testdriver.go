//go:build ignore

package opaque_api

import (
	"bufio"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/opaque_store"
	"log"
	"os"
	"strings"

	"github.com/drlzh/mng-app-user-auth-prot/utils/ghetto_db"
)

func readInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

// TestDriver runs a manual round-trip test using RN client interaction
func TestDriver() {
	// Set up in-memory DB and service
	db := ghetto_db.New()
	db.CreateTable(opaque_store.OpaqueClientTable)
	store := opaque_store.NewGhettoAdapter(db)
	opaqueSvc := NewDefaultOpaqueService(store)

	userIdentifier := "test-user@example.com"

	// Step 1: Registration — receive registrationRequest
	regReq := readInput("Paste `registrationRequest` from RN client: ")

	regResp, err := opaqueSvc.RegistrationStep1(userIdentifier, regReq)
	if err != nil {
		log.Fatalln("❌ RegistrationStep1 failed:", err)
	}
	fmt.Println("✅ registrationResponse (send to RN client):")
	fmt.Println(regResp)

	// Step 2: Receive registrationRecord
	regRecord := readInput("Paste `registrationRecord` from RN client: ")

	err = opaqueSvc.RegistrationStep2(userIdentifier, regRecord)
	if err != nil {
		log.Fatalln("❌ RegistrationStep2 failed:", err)
	}
	fmt.Println("✅ Registration complete.")

	// Step 3: Login — receive startLoginRequest
	startLogin := readInput("Paste `startLoginRequest` from RN client: ")

	loginResp, stateB64, err := opaqueSvc.LoginStep1(userIdentifier, startLogin)
	if err != nil {
		log.Fatalln("❌ LoginStep1 failed:", err)
	}
	fmt.Println("✅ loginResponse (send to RN client):")
	fmt.Println(loginResp)
	fmt.Println("✅ serverState (send to RN client and return with finishLoginRequest):")
	fmt.Println(stateB64)

	// Step 4: Receive finishLoginRequest
	finishLogin := readInput("Paste `finishLoginRequest` from RN client: ")

	sessionKey, err := opaqueSvc.LoginStep2(finishLogin, stateB64)
	if err != nil {
		log.Fatalln("❌ LoginStep2 failed:", err)
	}
	fmt.Println("✅ Login complete. Derived sessionKey:")
	fmt.Println(sessionKey)
}
