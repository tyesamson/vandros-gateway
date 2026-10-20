package relpath

import "testing"

func TestClean(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"":            "",
		".":           "",
		"/":           "",
		"reel.mov":    "reel.mov",
		"/job/deliv":  "job/deliv",
		"job/deliv/":  "job/deliv",
		"a/./b":       "a/b",
		"my reel.mov": "my reel.mov",
		// A leading slash is still inside the mount. It is not the host root.
		"/etc/passwd": "etc/passwd",
	}
	for in, want := range ok {
		got, err := Clean(in)
		if err != nil {
			t.Fatalf("Clean(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Fatalf("Clean(%q) = %q, want %q", in, got, want)
		}
	}

	escapes := []string{"..", "../secret", "job/../../secret", "a/../../b"}
	for _, in := range escapes {
		if _, err := Clean(in); err != ErrEscape {
			t.Fatalf("Clean(%q) error = %v, want ErrEscape", in, err)
		}
	}
	if _, err := Clean("ok\x00.mov"); err != ErrInvalid {
		t.Fatalf("null byte error = %v", err)
	}
}

func TestWithin(t *testing.T) {
	t.Parallel()
	if !Within("", "a/b") || !Within("a", "a") || !Within("a", "a/b") {
		t.Fatal("expected paths inside scope")
	}
	if Within("a", "ab") || Within("a/b", "a") || Within("a", "b") {
		t.Fatal("expected paths outside scope")
	}
}
