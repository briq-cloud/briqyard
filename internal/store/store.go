// Package store persists the daemon's state in one bbolt file: machines, tenants, endpoints.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrNotFound is returned for a missing record.
var ErrNotFound = errors.New("store: not found")

var (
	bMachines  = []byte("machines")
	bTenants   = []byte("tenants")
	bEndpoints = []byte("endpoints")
	bMeta      = []byte("meta")
)

// Store is the state database.
type Store struct {
	db *bolt.DB
}

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bMachines, bTenants, bEndpoints, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func put(tx *bolt.Tx, bucket []byte, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), data)
}

func get(tx *bolt.Tx, bucket []byte, key string, v any) error {
	data := tx.Bucket(bucket).Get([]byte(key))
	if data == nil {
		return ErrNotFound
	}
	return json.Unmarshal(data, v)
}

// Generic record access: the daemon defines the record types.

func (s *Store) PutMachine(key string, v any) error {
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx, bMachines, key, v) })
}

func (s *Store) GetMachine(key string, v any) error {
	return s.db.View(func(tx *bolt.Tx) error { return get(tx, bMachines, key, v) })
}

func (s *Store) DeleteMachine(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bMachines).Delete([]byte(key)) })
}

// EachMachine calls fn with every machine's raw JSON.
func (s *Store) EachMachine(fn func(key string, data []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bMachines).ForEach(func(k, v []byte) error { return fn(string(k), v) })
	})
}

func (s *Store) PutTenant(key string, v any) error {
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx, bTenants, key, v) })
}

func (s *Store) GetTenant(key string, v any) error {
	return s.db.View(func(tx *bolt.Tx) error { return get(tx, bTenants, key, v) })
}

func (s *Store) DeleteTenant(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bTenants).Delete([]byte(key)) })
}

func (s *Store) EachTenant(fn func(key string, data []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bTenants).ForEach(func(k, v []byte) error { return fn(string(k), v) })
	})
}

func (s *Store) PutEndpoint(key string, v any) error {
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx, bEndpoints, key, v) })
}

func (s *Store) GetEndpoint(key string, v any) error {
	return s.db.View(func(tx *bolt.Tx) error { return get(tx, bEndpoints, key, v) })
}

func (s *Store) DeleteEndpoint(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bEndpoints).Delete([]byte(key)) })
}

func (s *Store) EachEndpoint(fn func(key string, data []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bEndpoints).ForEach(func(k, v []byte) error { return fn(string(k), v) })
	})
}

// GetMeta and PutMeta keep small values: the host id, counters.
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bMeta).Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		v = string(data)
		return nil
	})
	return v, err
}

func (s *Store) PutMeta(key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bMeta).Put([]byte(key), []byte(value)) })
}
