package storage

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyesamson/vandros-gateway/config"
)

func TestJailAndRange(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "in.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "leak")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outdir")); err != nil {
		t.Fatal(err)
	}
	// Relative links that stay inside the mount are readable.
	// os.Root rejects absolute symlinks even when the target is inside.
	if err := os.Symlink("sub/in.txt", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 256*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	portal, err := Open([]config.Mount{{ID: "promise", Name: "Promise", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	mount, ok := portal.Get("promise")
	if !ok {
		t.Fatal("missing mount")
	}

	f, _, err := mount.OpenFile("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	f.Close()
	if string(body) != "hello" {
		t.Fatalf("ok.txt = %q", body)
	}

	f, _, err = mount.OpenFile("alias")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(f)
	f.Close()
	if string(body) != "inside" {
		t.Fatalf("alias = %q", body)
	}

	for _, rel := range []string{"../secret.txt", "sub/../../secret.txt", "leak", "leak/", "outdir/secret.txt", "ok.txt\x00.jpg"} {
		f, _, err := mount.OpenFile(rel)
		if err == nil {
			got, _ := io.ReadAll(f)
			f.Close()
			t.Fatalf("OpenFile(%q) succeeded with %q", rel, got)
		}
	}
	if _, err := mount.List("outdir"); err == nil {
		t.Fatal("listed a directory symlink that leaves the mount")
	}

	entries, err := mount.List("")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Entry{}
	for _, ent := range entries {
		names[ent.Name] = ent
		if strings.Contains(ent.Rel, "secret") {
			t.Fatalf("listing leaked %q", ent.Rel)
		}
	}
	leak, ok := names["leak"]
	if !names["sub"].IsDir || !ok || !leak.Broken || !names["alias"].IsLink {
		t.Fatalf("listing flags = %#v", names)
	}

	f, info, err := mount.OpenFile("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	req := httptest.NewRequest(http.MethodGet, "/d/promise/big.bin", nil)
	req.Header.Set("Range", "bytes=-4")
	rr := httptest.NewRecorder()
	Serve(rr, req, "big.bin", info.ModTime(), f)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := rr.Body.Bytes(); string(got) != string(payload[len(payload)-4:]) {
		t.Fatalf("range body = %v, want last 4 bytes", got)
	}
	if rr.Body.Len() != 4 {
		t.Fatalf("range length = %d", rr.Body.Len())
	}
	if rr.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content type = %s", rr.Header().Get("Content-Type"))
	}
}

func TestCanonicalFollowsLinksInsideTheMount(t *testing.T) {
	root := t.TempDir()
	job := filepath.Join(root, "Project_X", "Deliverables")
	if err := os.MkdirAll(job, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "reel.mov"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../secret.txt", filepath.Join(job, "via")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("reel.mov", filepath.Join(job, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop-b", filepath.Join(job, "loop-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop-a", filepath.Join(job, "loop-b")); err != nil {
		t.Fatal(err)
	}

	portal, err := Open([]config.Mount{{ID: "promise", Name: "Promise", Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	mount, ok := portal.Get("promise")
	if !ok {
		t.Fatal("missing mount")
	}

	if got, err := mount.Canonical("Project_X/Deliverables/via"); err != nil || got != "secret.txt" {
		t.Fatalf("via = %q, %v", got, err)
	}
	if got, err := mount.Canonical("Project_X/Deliverables/alias"); err != nil || got != "Project_X/Deliverables/reel.mov" {
		t.Fatalf("alias = %q, %v", got, err)
	}
	if _, err := mount.Canonical("Project_X/Deliverables/loop-a"); err == nil {
		t.Fatal("symlink loop was accepted")
	}
}
