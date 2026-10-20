package relpath

import (
	"errors"
	"path"
	"strings"
)

var (
	ErrEscape  = errors.New("path escapes root")
	ErrInvalid = errors.New("invalid path")
)

// Clean returns a slash-separated path relative to a mount.
// The mount root is an empty string. Null bytes and paths that leave
// the mount are rejected before any filesystem call.
func Clean(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", ErrInvalid
	}
	name = strings.Trim(name, "/")
	if name == "" || name == "." {
		return "", nil
	}
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "", nil
	}
	if path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrEscape
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", ErrEscape
		}
	}
	return cleaned, nil
}

// Within reports whether rel is scope or a file beneath it.
// Both arguments must already have been passed through Clean.
// An empty scope is the whole mount.
func Within(scope, rel string) bool {
	if scope == "" {
		return true
	}
	return rel == scope || strings.HasPrefix(rel, scope+"/")
}
