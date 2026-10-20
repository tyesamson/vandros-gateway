package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/internal/relpath"
	_ "modernc.org/sqlite"
)

const (
	RoleAdmin  = "admin"
	RoleClient = "client"
	CookieName = "vandros_session"

	PermRead Perm = iota
	PermWrite
	PermDelete
)

// Perm is one capability on a scope.
type Perm int

// Scope is a directory a client may use, relative to a mount.
// An empty Path is the whole mount.
type Scope struct {
	ID      int64
	MountID string
	Path    string
	Read    bool
	Write   bool
	Delete  bool
}

// User is an authenticated account and its scopes.
type User struct {
	ID       int64
	Username string
	Role     string
	Scopes   []Scope
}

// Allows reports whether the user may perform perm on rel inside mountID.
func (u User) Allows(mountID, rel string, perm Perm) bool {
	cleaned, err := relpath.Clean(rel)
	if err != nil {
		return false
	}
	if u.Role == RoleAdmin {
		return true
	}
	for _, scope := range u.Scopes {
		if scope.MountID != mountID || !scope.allows(perm) {
			continue
		}
		scopePath, err := relpath.Clean(scope.Path)
		if err != nil {
			continue
		}
		if relpath.Within(scopePath, cleaned) {
			return true
		}
	}
	return false
}

func (s Scope) allows(perm Perm) bool {
	switch perm {
	case PermRead:
		return s.Read
	case PermWrite:
		return s.Write
	case PermDelete:
		return s.Delete
	default:
		return false
	}
}

var (
	ErrCredentials = errors.New("credentials not accepted")
	ErrNoSession   = errors.New("no session")
)

// Store is the SQLite record of users, scopes, and sessions.
// It does not store file metadata.
type Store struct {
	db        *sql.DB
	secret    []byte
	dummyHash string
}

// Open creates the database file if needed and applies migrations.
// secret peppers session token hashes and must be at least 32 characters.
func Open(path, secret string) (*Store, error) {
	if len(secret) < 32 {
		return nil, errors.New("session secret must be at least 32 characters")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("database directory: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	dummy, err := HashPassword(randomPassword())
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, secret: []byte(secret), dummyHash: dummy}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// EnsureAdmin creates the first administrator when the database has no users.
func (s *Store) EnsureAdmin(ctx context.Context, username, password string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if username == "" {
		username = "admin"
	}
	if password == "" {
		return errors.New("database has no users; set VANDROS_ADMIN_USER and VANDROS_ADMIN_PASSWORD")
	}
	_, err := s.CreateUser(ctx, username, password, RoleAdmin, nil)
	return err
}

// CreateUser inserts an account. Administrators have no scopes.
// Clients need at least one scope with a permission set.
func (s *Store) CreateUser(ctx context.Context, username, password, role string, scopes []Scope) (User, error) {
	if !validUsername(username) {
		return User{}, errors.New("invalid username")
	}
	if role != RoleAdmin && role != RoleClient {
		return User{}, errors.New("invalid role")
	}
	if role == RoleAdmin && len(scopes) > 0 {
		return User{}, errors.New("administrators do not take scopes")
	}
	for i := range scopes {
		if !config.ValidMountID(scopes[i].MountID) {
			return User{}, fmt.Errorf("invalid mount id %q", scopes[i].MountID)
		}
		cleaned, err := relpath.Clean(scopes[i].Path)
		if err != nil {
			return User{}, fmt.Errorf("scope path: %w", err)
		}
		if !scopes[i].Read && !scopes[i].Write && !scopes[i].Delete {
			return User{}, errors.New("a scope needs a permission")
		}
		scopes[i].Path = cleaned
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, hash, role, time.Now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, fmt.Errorf("user %s already exists", username)
		}
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	for _, scope := range scopes {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO scopes(user_id, mount_id, path, can_read, can_write, can_delete) VALUES (?, ?, ?, ?, ?, ?)`,
			id, scope.MountID, scope.Path, boolInt(scope.Read), boolInt(scope.Write), boolInt(scope.Delete))
		if err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.userByID(ctx, id)
}

// Authenticate checks a username and password.
// Missing users take the same hash verification path as real users.
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	var id int64
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE username = ?`, username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = VerifyPassword(password, s.dummyHash)
		return User{}, ErrCredentials
	}
	if err != nil {
		return User{}, err
	}
	ok, err := VerifyPassword(password, hash)
	if err != nil || !ok {
		return User{}, ErrCredentials
	}
	return s.userByID(ctx, id)
}

// CreateSession stores a new session and returns the cookie token.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		s.hashToken(token), userID, expires.Unix())
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// UserFromToken loads the user for a cookie token.
func (s *Store) UserFromToken(ctx context.Context, token string) (User, error) {
	if token == "" {
		return User{}, ErrNoSession
	}
	now := time.Now().Unix()
	var userID, expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, s.hashToken(token)).Scan(&userID, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expires <= now) {
		if err == nil {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, s.hashToken(token))
		}
		return User{}, ErrNoSession
	}
	if err != nil {
		return User{}, err
	}
	return s.userByID(ctx, userID)
}

// DeleteSession removes a cookie token.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, s.hashToken(token))
	return err
}

func (s *Store) userByID(ctx context.Context, id int64) (User, error) {
	var user User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, role FROM users WHERE id = ?`, id).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		return User{}, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, mount_id, path, can_read, can_write, can_delete FROM scopes WHERE user_id = ? ORDER BY id`, id)
	if err != nil {
		return User{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope Scope
		var read, write, del int
		if err := rows.Scan(&scope.ID, &scope.MountID, &scope.Path, &read, &write, &del); err != nil {
			return User{}, err
		}
		scope.Read = read == 1
		scope.Write = write == 1
		scope.Delete = del == 1
		user.Scopes = append(user.Scopes, scope)
	}
	return user, rows.Err()
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER NOT NULL PRIMARY KEY)`); err != nil {
		return err
	}
	if err := applyMigration(db, 1, `
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'client')),
    created_at INTEGER NOT NULL
);
CREATE TABLE scopes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mount_id TEXT NOT NULL,
    path TEXT NOT NULL,
    can_read INTEGER NOT NULL CHECK (can_read IN (0, 1)),
    can_write INTEGER NOT NULL CHECK (can_write IN (0, 1)),
    can_delete INTEGER NOT NULL CHECK (can_delete IN (0, 1)),
    UNIQUE (user_id, mount_id, path)
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expires ON sessions(expires_at);
`); err != nil {
		return err
	}
	return applyMigration(db, 2, `
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`)
}

func applyMigration(db *sql.DB, version int, sqlText string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, version).Scan(&n); err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(sqlText); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES (?)`, version); err != nil {
		return err
	}
	return tx.Commit()
}

func sqliteDSN(path string) string {
	q := url.Values{}
	q.Set("mode", "rwc")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "cache_size(-2000)")
	return (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
}

func (s *Store) hashToken(token string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "vandros-dummy-password-not-used"
	}
	return hex.EncodeToString(b)
}

func validUsername(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '.' || r == '_' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
