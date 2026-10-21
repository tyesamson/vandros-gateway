package auth

import (
	"path/filepath"
	"testing"
)

func TestSettingsRecords(t *testing.T) {
	store := openTestStore(t)
	ctx := t.Context()
	admin, err := store.CreateUser(ctx, "alastair", "correct-horse-battery", RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureBranding(ctx, "Vandros Gateway"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(ctx, "brand_name", "Portal"); err != nil {
		t.Fatal(err)
	}
	name, ok, err := store.Setting(ctx, "brand_name")
	if err != nil || !ok || name != "Portal" {
		t.Fatalf("brand = %q ok=%v err=%v", name, ok, err)
	}
	client, err := store.CreateUser(ctx, "client_abc", "correct-horse-battery", RoleClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddScope(ctx, client.ID, Scope{MountID: "library", Path: "client/Deliverables", Read: true}); err != nil {
		t.Fatal(err)
	}
	got, err := store.userByID(ctx, client.ID)
	if err != nil || len(got.Scopes) != 1 || got.Scopes[0].ID == 0 {
		t.Fatalf("scope = %+v err=%v", got.Scopes, err)
	}
	if err := store.DeleteUser(ctx, admin.ID, admin.ID); err == nil {
		t.Fatal("deleted own account")
	}
	if err := store.DeleteUser(ctx, admin.ID, client.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMigratesExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portal.db")
	openAt(t, path)
	second := openAt(t, path)
	if err := second.EnsureBranding(t.Context(), "Vandros Gateway"); err != nil {
		t.Fatal(err)
	}
}

func openAt(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path, "test-session-secret-at-least-32-characters")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}
