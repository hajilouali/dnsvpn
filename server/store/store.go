// Package store is the SQLite-backed user database. It persists users, their auth
// tokens and limits, and usage, and implements engine.Authorizer / engine.Accountant
// so the tunnel enforces per-user access, expiry, quota and concurrency.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// User is a tunnel account.
type User struct {
	ID            int64
	Username      string
	Token         string
	Enabled       bool
	ExpiresAt     *time.Time // nil => never
	QuotaBytes    int64      // 0 => unlimited
	UsedBytes     int64
	MaxConcurrent int        // 0 => unlimited
	CreatedAt     time.Time
}

// Store wraps the database plus in-memory live-concurrency counters.
type Store struct {
	db *sql.DB

	mu      sync.Mutex
	active  map[string]int // token -> current concurrent streams
}

// Open opens (creating if needed) the SQLite database at path and migrates schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc sqlite is happiest serialized
	s := &Store{db: db, active: make(map[string]int)}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  username       TEXT UNIQUE NOT NULL,
  token          TEXT UNIQUE NOT NULL,
  enabled        INTEGER NOT NULL DEFAULT 1,
  expires_at     INTEGER,            -- unix seconds, NULL = never
  quota_bytes    INTEGER NOT NULL DEFAULT 0,
  used_bytes     INTEGER NOT NULL DEFAULT 0,
  max_concurrent INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);`)
	return err
}

// GetSetting returns a stored setting and whether it was present.
func (s *Store) GetSetting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting inserts or updates a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

// NewToken returns a random 128-bit hex token.
func NewToken() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// CreateUser inserts a user; a random token is generated if token is empty.
func (s *Store) CreateUser(username, token string, quota int64, maxConc int, expires *time.Time) (*User, error) {
	if username == "" {
		return nil, errors.New("store: empty username")
	}
	if token == "" {
		token = NewToken()
	}
	var exp *int64
	if expires != nil {
		e := expires.Unix()
		exp = &e
	}
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO users(username,token,enabled,expires_at,quota_bytes,used_bytes,max_concurrent,created_at)
		 VALUES(?,?,1,?,?,0,?,?)`,
		username, token, exp, quota, maxConc, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetUser(id)
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var enabled int
	var exp sql.NullInt64
	var created int64
	if err := row.Scan(&u.ID, &u.Username, &u.Token, &enabled, &exp,
		&u.QuotaBytes, &u.UsedBytes, &u.MaxConcurrent, &created); err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	if exp.Valid {
		t := time.Unix(exp.Int64, 0)
		u.ExpiresAt = &t
	}
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

const userCols = `id,username,token,enabled,expires_at,quota_bytes,used_bytes,max_concurrent,created_at`

func (s *Store) GetUser(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) userByToken(token string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE token=?`, token))
}

// ListUsers returns all users ordered by id.
func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetEnabled toggles a user.
func (s *Store) SetEnabled(id int64, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := s.db.Exec(`UPDATE users SET enabled=? WHERE id=?`, e, id)
	return err
}

// UpdateLimits sets quota/concurrency/expiry for a user.
func (s *Store) UpdateLimits(id int64, quota int64, maxConc int, expires *time.Time) error {
	var exp *int64
	if expires != nil {
		e := expires.Unix()
		exp = &e
	}
	_, err := s.db.Exec(`UPDATE users SET quota_bytes=?, max_concurrent=?, expires_at=? WHERE id=?`,
		quota, maxConc, exp, id)
	return err
}

// ResetUsage zeroes a user's used bytes.
func (s *Store) ResetUsage(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET used_bytes=0 WHERE id=?`, id)
	return err
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// --- engine.Authorizer / engine.Accountant ----------------------------------

// ErrDenied is returned when a token is rejected.
var ErrDenied = errors.New("store: access denied")

// Authorize validates a token against enabled/expiry/quota/concurrency and reserves
// a concurrency slot, returning a release func that frees it.
func (s *Store) Authorize(token string) (func(), error) {
	u, err := s.userByToken(token)
	if err != nil {
		return nil, ErrDenied
	}
	if !u.Enabled {
		return nil, fmt.Errorf("%w: disabled", ErrDenied)
	}
	if u.ExpiresAt != nil && time.Now().After(*u.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired", ErrDenied)
	}
	if u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes {
		return nil, fmt.Errorf("%w: quota exhausted", ErrDenied)
	}
	s.mu.Lock()
	if u.MaxConcurrent > 0 && s.active[token] >= u.MaxConcurrent {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: too many connections", ErrDenied)
	}
	s.active[token]++
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if s.active[token] > 0 {
			s.active[token]--
		}
		s.mu.Unlock()
	}, nil
}

// Account adds transferred bytes to the user's usage.
func (s *Store) Account(token string, up, down int64) {
	s.db.Exec(`UPDATE users SET used_bytes = used_bytes + ? WHERE token=?`, up+down, token)
}

// ActiveCount returns the current concurrent-stream count for a token.
func (s *Store) ActiveCount(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[token]
}
