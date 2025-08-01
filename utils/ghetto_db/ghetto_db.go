package ghetto_db

import (
	"fmt"
	"sync"
)

// GhettoDB simulates a PostgreSQL-like table-based key-value store in memory.
type GhettoDB struct {
	tables map[string]map[string][]byte
	mu     sync.RWMutex
}

// New returns a new instance of GhettoDB.
func New() *GhettoDB {
	return &GhettoDB{
		tables: make(map[string]map[string][]byte),
	}
}

// CreateTable creates a new table if it doesn't exist.
func (db *GhettoDB) CreateTable(name string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.tables[name]; !ok {
		db.tables[name] = make(map[string][]byte)
	}
}

// Insert inserts a row (key, value) into the specified table.
func (db *GhettoDB) Insert(table, key string, value []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tbl, ok := db.tables[table]
	if !ok {
		return fmt.Errorf("table not found: %s", table)
	}

	if _, exists := tbl[key]; exists {
		return fmt.Errorf("duplicate key: %s", key)
	}

	tbl[key] = value
	return nil
}

// Upsert inserts or updates a row.
func (db *GhettoDB) Upsert(table, key string, value []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tbl, ok := db.tables[table]
	if !ok {
		return fmt.Errorf("table not found: %s", table)
	}

	tbl[key] = value
	return nil
}

// Get returns a value by key from the specified table.
func (db *GhettoDB) Get(table, key string) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	tbl, ok := db.tables[table]
	if !ok {
		return nil, fmt.Errorf("table not found: %s", table)
	}

	val, ok := tbl[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	return val, nil
}

// Delete removes a key from the specified table.
func (db *GhettoDB) Delete(table, key string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tbl, ok := db.tables[table]
	if !ok {
		return fmt.Errorf("table not found: %s", table)
	}

	if _, exists := tbl[key]; !exists {
		return fmt.Errorf("key not found: %s", key)
	}

	delete(tbl, key)
	return nil
}

// ListKeys returns all keys in a table.
func (db *GhettoDB) ListKeys(table string) ([]string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	tbl, ok := db.tables[table]
	if !ok {
		return nil, fmt.Errorf("table not found: %s", table)
	}

	keys := make([]string, 0, len(tbl))
	for k := range tbl {
		keys = append(keys, k)
	}

	return keys, nil
}

// DropTable removes an entire table.
func (db *GhettoDB) DropTable(name string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.tables[name]; !ok {
		return fmt.Errorf("table not found: %s", name)
	}

	delete(db.tables, name)
	return nil
}

// Exists checks if a key exists in the table.
func (db *GhettoDB) Exists(table, key string) (bool, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	tbl, ok := db.tables[table]
	if !ok {
		return false, fmt.Errorf("table not found: %s", table)
	}

	_, ok = tbl[key]
	return ok, nil
}
