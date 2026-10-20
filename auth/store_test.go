package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionAndScope(t *testing.T) {
	store := openTestStore(t)
	ctx := t.Context()
	admin, err := store.CreateUser(ctx, "alastair", "correct-horse-battery", RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureAdmin(ctx, "other", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateUser(ctx, "client_abc", "correct-horse-battery", RoleClient, []Scope{{
		MountID: "promise",
		Path:    "Project_X/Deliverables",
		Read:    true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if admin.Allows("promise", "../secret", PermRead) {
		t.Fatal("admin allowed an escaping path")
	}
	if !admin.Allows("promise", "anywhere", PermDelete) {
		t.Fatal("admin should be allowed inside a mount")
	}
	if !client.Allows("promise", "Project_X/Deliverables/reel.mov", PermRead) {
		t.Fatal("client should read inside the scope")
	}
	if client.Allows("promise", "Project_X", PermRead) || client.Allows("promise", "secret", PermRead) || client.Allows("fileserv", "Project_X/Deliverables", PermRead) {
		t.Fatal("client scope leaked")
	}
	if client.Allows("promise", "Project_X/Deliverables/reel.mov", PermWrite) {
		t.Fatal("read scope granted write")
	}

	token, _, err := store.CreateSession(ctx, client.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.UserFromToken(ctx, token)
	if err != nil || got.Username != "client_abc" || len(got.Scopes) != 1 {
		t.Fatalf("session user = %+v err=%v", got, err)
	}
	if err := store.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UserFromToken(ctx, token); err != ErrNoSession {
		t.Fatalf("deleted session error = %v", err)
	}

	if _, err := store.Authenticate(ctx, "missing", "correct-horse-battery"); err != ErrCredentials {
		t.Fatalf("missing user error = %v", err)
	}
	if _, err := store.Authenticate(ctx, "alastair", "wrong-horse-battery"); err != ErrCredentials {
		t.Fatalf("bad password error = %v", err)
	}
	if _, err := store.Authenticate(ctx, "Alastair", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
}

func TestForeignKeys(t *testing.T) {
	store := openTestStore(t)
	ctx := t.Context()
	user, err := store.CreateUser(ctx, "client_abc", "correct-horse-battery", RoleClient, []Scope{{
		MountID: "promise", Path: "job", Read: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM scopes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("scopes left after user delete: %d", n)
	}
	var mode string
	if err := store.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %s", mode)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "portal.db"), "test-session-secret-at-least-32-chars")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}
