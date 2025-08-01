package ghetto_db

import (
	"testing"
)

func TestGhettoDB_BasicOps(t *testing.T) {
	db := New()
	table := "test_table"
	db.CreateTable(table)

	key := "foo@example.com"
	value := []byte("hello world")

	// Insert
	if err := db.Insert(table, key, value); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Get
	got, err := db.Get(table, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Expected %q, got %q", value, got)
	}

	// Upsert
	newVal := []byte("updated")
	if err := db.Upsert(table, key, newVal); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	got, _ = db.Get(table, key)
	if string(got) != string(newVal) {
		t.Errorf("Expected updated %q, got %q", newVal, got)
	}

	// Exists
	exists, _ := db.Exists(table, key)
	if !exists {
		t.Errorf("Expected key to exist")
	}

	// ListKeys
	keys, _ := db.ListKeys(table)
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("Expected keys [%s], got %v", key, keys)
	}

	// Delete
	if err := db.Delete(table, key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = db.Get(table, key)
	if err == nil {
		t.Errorf("Expected error on Get after delete")
	}

	// DropTable
	if err := db.DropTable(table); err != nil {
		t.Fatalf("DropTable failed: %v", err)
	}

	if _, err := db.ListKeys(table); err == nil {
		t.Errorf("Expected error on ListKeys after table drop")
	}
}
