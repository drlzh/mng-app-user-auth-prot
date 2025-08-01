package ghetto_db

import (
	"fmt"
	"log"
)

func TestDriver() {
	db := New()
	table := "opaque_users"
	db.CreateTable(table)

	key := "user@example.com"
	val := []byte("opaque-client-record")

	fmt.Println("⏳ Inserting key...")
	if err := db.Insert(table, key, val); err != nil {
		log.Fatalln("Insert failed:", err)
	}
	fmt.Println("✅ Inserted.")

	fmt.Println("🔁 Reading value back...")
	out, err := db.Get(table, key)
	if err != nil {
		log.Fatalln("Get failed:", err)
	}
	fmt.Printf("🔎 Retrieved value: %s\n", string(out))

	fmt.Println("✏️ Upserting new value...")
	newVal := []byte("updated-record")
	if err := db.Upsert(table, key, newVal); err != nil {
		log.Fatalln("Upsert failed:", err)
	}
	fmt.Println("✅ Upserted.")

	fmt.Println("🧪 Verifying update...")
	out, _ = db.Get(table, key)
	fmt.Printf("🔎 Updated value: %s\n", string(out))

	fmt.Println("🔑 Listing all keys...")
	keys, _ := db.ListKeys(table)
	fmt.Printf("📦 Keys: %v\n", keys)

	fmt.Println("🧨 Deleting key...")
	if err := db.Delete(table, key); err != nil {
		log.Fatalln("Delete failed:", err)
	}
	fmt.Println("✅ Deleted.")

	fmt.Println("❓ Checking key existence...")
	exists, _ := db.Exists(table, key)
	fmt.Printf("🔍 Exists after delete? %v\n", exists)

	fmt.Println("🧹 Dropping table...")
	if err := db.DropTable(table); err != nil {
		log.Fatalln("DropTable failed:", err)
	}
	fmt.Println("✅ Table dropped.")
}
