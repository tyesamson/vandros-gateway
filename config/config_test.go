package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMounts(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	nested := filepath.Join(a, "child")
	for _, dir := range []string{a, b, nested} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	db := filepath.Join(root, "portal.db")

	cfg, err := Parse([]byte(yamlMounts(db, a, b)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.SessionTTL != 12*time.Hour || cfg.BrandName != "The Finish" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if len(cfg.Mounts) != 2 || cfg.Mounts[0].ID != "promise" {
		t.Fatalf("mounts = %+v", cfg.Mounts)
	}

	if _, err := Parse([]byte(yamlMounts(db, a, nested))); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("nested mounts error = %v", err)
	}
	if _, err := Parse([]byte("listen: \":8080\"\ndatabase:\n  path: " + db + "\nmounts: []\n")); err == nil {
		t.Fatal("empty mounts accepted")
	}
	if _, err := Parse([]byte("listen: \":8080\"\nnope: true\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func yamlMounts(db, a, b string) string {
	return fmt.Sprintf("database:\n  path: %q\nbranding:\n  name: The Finish\nmounts:\n  - id: promise\n    name: Promise\n    path: %q\n  - id: fileserv\n    name: Fileserv\n    path: %q\n", db, a, b)
}
