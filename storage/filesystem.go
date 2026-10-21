// Package storage is a window onto host mounts.
// Listings are read from the filesystem on every request. File bytes are
// not copied into memory and nothing about the tree is written to the database.
//
// Paths are opened through os.Root, which rejects "..", absolute symlinks,
// and symlinks whose target is outside the mount. Clean is still applied
// first so a trailing slash or a null byte never reaches the kernel.
//
// os.Root does not block bind mounts created by the host administrator.
// Those require privileges the portal user does not have.
package storage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/internal/relpath"
)

var (
	ErrNotFile = fmt.Errorf("not a file")
	ErrNotDir  = fmt.Errorf("not a directory")
	ErrExists  = fmt.Errorf("file already exists")
)

// Entry is one live directory record. Symlink targets are not exposed.
type Entry struct {
	Name    string
	Rel     string
	Size    int64
	ModTime time.Time
	IsDir   bool
	IsLink  bool
	Broken  bool
}

// Portal is the set of configured mounts.
type Portal struct {
	mounts map[string]*mount
	order  []string
}

type mount struct {
	id   string
	name string
	root *os.Root
}

// Mount is a handle to one host directory.
type Mount struct {
	m *mount
}

// Open opens each mount directory and holds it for the life of the process.
func Open(mounts []config.Mount) (*Portal, error) {
	p := &Portal{mounts: make(map[string]*mount, len(mounts))}
	for _, cfg := range mounts {
		root, err := os.OpenRoot(cfg.Path)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("mount %s: %w", cfg.ID, err)
		}
		p.mounts[cfg.ID] = &mount{id: cfg.ID, name: cfg.Name, root: root}
		p.order = append(p.order, cfg.ID)
	}
	return p, nil
}

// Close releases every mount.
func (p *Portal) Close() error {
	if p == nil {
		return nil
	}
	var err error
	for _, id := range p.order {
		m := p.mounts[id]
		if m != nil && m.root != nil {
			err = errors.Join(err, m.root.Close())
			m.root = nil
		}
	}
	return err
}

// Get returns the mount with the given id.
func (p *Portal) Get(id string) (Mount, bool) {
	m, ok := p.mounts[id]
	if !ok || m.root == nil {
		return Mount{}, false
	}
	return Mount{m: m}, true
}

// Mounts returns the configured mounts in config order.
func (p *Portal) Mounts() []Mount {
	out := make([]Mount, 0, len(p.order))
	for _, id := range p.order {
		if m, ok := p.Get(id); ok {
			out = append(out, m)
		}
	}
	return out
}

// ID is the URL-safe mount id.
func (m Mount) ID() string {
	if m.m == nil {
		return ""
	}
	return m.m.id
}

// Name is the label shown in the portal.
func (m Mount) Name() string {
	if m.m == nil {
		return ""
	}
	return m.m.name
}

// OpenFile opens a regular file inside the mount for streaming.
// The caller closes the file. Directories and escaping paths return an error.
func (m Mount) OpenFile(rel string) (*os.File, fs.FileInfo, error) {
	if m.m == nil || m.m.root == nil {
		return nil, nil, os.ErrNotExist
	}
	name, err := cleanRoot(rel)
	if err != nil {
		return nil, nil, err
	}
	f, err := m.m.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		f.Close()
		return nil, info, ErrNotFile
	}
	return f, info, nil
}

// CreateExclusive creates a regular file at dir/name and returns it for writing.
// name must be a single path segment. An existing file, directory, or symlink
// is left untouched.
func (m Mount) CreateExclusive(dir, name string) (*os.File, error) {
	if m.m == nil || m.m.root == nil {
		return nil, os.ErrNotExist
	}
	if !oneSegment(name) {
		return nil, relpath.ErrEscape
	}
	parent, err := cleanRoot(dir)
	if err != nil {
		return nil, err
	}
	info, err := m.m.root.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrNotDir
	}
	f, err := m.m.root.OpenFile(rootName(joinRel(dir, name)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil, ErrExists
		}
		return nil, err
	}
	return f, nil
}

// RemoveFile removes a regular file. Directories, symlinks, and other nodes
// are left in place.
func (m Mount) RemoveFile(rel string) error {
	if m.m == nil || m.m.root == nil {
		return os.ErrNotExist
	}
	name, err := cleanRoot(rel)
	if err != nil {
		return err
	}
	info, err := m.m.root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrNotFile
	}
	return m.m.root.Remove(name)
}

// List reads the directory at rel. The result is not cached.
func (m Mount) List(rel string) ([]Entry, error) {
	if m.m == nil || m.m.root == nil {
		return nil, os.ErrNotExist
	}
	name, err := cleanRoot(rel)
	if err != nil {
		return nil, err
	}
	dir, err := relpath.Clean(rel)
	if err != nil {
		return nil, err
	}
	f, err := m.m.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, ErrNotDir
	}
	dents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(dents))
	for _, d := range dents {
		child := d.Name()
		if child == "" || child == "." || child == ".." || strings.ContainsAny(child, "/\\\x00") {
			continue
		}
		meta, err := d.Info()
		if err != nil {
			continue
		}
		ent := Entry{
			Name:    child,
			Rel:     joinRel(dir, child),
			ModTime: meta.ModTime(),
		}
		if meta.Mode()&os.ModeSymlink != 0 {
			ent.IsLink = true
			st, err := m.m.root.Stat(rootName(ent.Rel))
			if err != nil {
				ent.Broken = true
				entries = append(entries, ent)
				continue
			}
			ent.IsDir = st.IsDir()
			ent.ModTime = st.ModTime()
			if !st.IsDir() {
				ent.Size = st.Size()
			}
			entries = append(entries, ent)
			continue
		}
		ent.IsDir = meta.IsDir()
		if !ent.IsDir {
			ent.Size = meta.Size()
		}
		entries = append(entries, ent)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		li := strings.ToLower(entries[i].Name)
		lj := strings.ToLower(entries[j].Name)
		if li != lj {
			return li < lj
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// Canonical returns rel with every symlink walked, still relative to the mount.
// Callers that enforce a subdirectory scope must check this path, not only the
// path the client typed. os.Root already refuses links that leave the mount.
func (m Mount) Canonical(rel string) (string, error) {
	if m.m == nil || m.m.root == nil {
		return "", os.ErrNotExist
	}
	cleaned, err := relpath.Clean(rel)
	if err != nil {
		return "", err
	}
	return m.resolve(cleaned, 0)
}

// Serve streams f to w, including HTTP Range responses.
// f must be the live file from OpenFile. Its contents are not buffered.
// The type is forced to octet-stream so a stored HTML or SVG file is downloaded
// rather than rendered.
func Serve(w http.ResponseWriter, r *http.Request, name string, mod time.Time, f io.ReadSeeker) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", ContentDisposition(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private")
	http.ServeContent(w, r, name, mod, f)
}

const maxSymlinkHops = 40

func (m Mount) resolve(rel string, depth int) (string, error) {
	if rel == "" {
		return "", nil
	}
	parts := strings.Split(rel, "/")
	acc := ""
	for i, seg := range parts {
		next := joinRel(acc, seg)
		info, err := m.m.root.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) {
				return relpath.Clean(joinRel(acc, strings.Join(parts[i:], "/")))
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			acc = next
			continue
		}
		if depth >= maxSymlinkHops {
			return "", relpath.ErrEscape
		}
		target, err := m.m.root.Readlink(next)
		if err != nil {
			return "", err
		}
		if target == "" || strings.ContainsRune(target, 0) || strings.HasPrefix(target, "/") {
			return "", relpath.ErrEscape
		}
		joined, err := relpath.Clean(path.Join(acc, target))
		if err != nil {
			return "", err
		}
		rest := strings.Join(parts[i+1:], "/")
		combined := joined
		if rest != "" {
			combined = joinRel(joined, rest)
		}
		combined, err = relpath.Clean(combined)
		if err != nil {
			return "", err
		}
		return m.resolve(combined, depth+1)
	}
	return acc, nil
}

func cleanRoot(rel string) (string, error) {
	cleaned, err := relpath.Clean(rel)
	if err != nil {
		return "", err
	}
	return rootName(cleaned), nil
}

func rootName(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}

func oneSegment(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00") && path.Base(name) == name
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func ContentDisposition(name string) string {
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, base)
	if cleaned == "" || cleaned == "." {
		cleaned = "download"
	}
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, cleaned)
	if ascii == "" {
		ascii = "download"
	}
	return "attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + url.PathEscape(cleaned)
}
