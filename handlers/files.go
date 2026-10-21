package handlers

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/internal/relpath"
	"github.com/tyesamson/vandros-gateway/storage"
)

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	links := s.entryPoints(user)
	if len(links) == 1 {
		http.Redirect(w, r, links[0].Href, http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "mounts", page{Username: user.Username, Mounts: links})
}

func (s *Server) browse(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, rel, resolved, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	if resolved != rel {
		http.Redirect(w, r, browseURL(mount.ID(), resolved), http.StatusTemporaryRedirect)
		return
	}
	entries, err := mount.List(resolved)
	if err != nil {
		writeFSError(s.Log, w, r, err)
		return
	}
	prefix, _ := readPrefix(user, mount.ID(), rel)
	rows := make([]row, 0, len(entries))
	hasFiles := false
	for _, ent := range entries {
		item := row{
			Name:     ent.Name,
			Modified: formatTime(ent.ModTime),
			Size:     "—",
		}
		switch {
		case ent.IsLink:
			target, err := mount.Canonical(ent.Rel)
			if err != nil || !user.Allows(mount.ID(), target, auth.PermRead) {
				continue
			}
			if ent.IsDir {
				item.Href = browseURL(mount.ID(), target)
				item.Class = "dir"
			} else if !ent.Broken {
				item.Href = downloadURL(mount.ID(), target)
				item.Download = item.Href
				item.Size = humanSize(ent.Size)
				hasFiles = true
			}
		case ent.IsDir:
			item.Href = browseURL(mount.ID(), ent.Rel)
			item.Class = "dir"
		default:
			item.Href = downloadURL(mount.ID(), ent.Rel)
			item.Download = item.Href
			item.Size = humanSize(ent.Size)
			hasFiles = true
		}
		rows = append(rows, item)
	}
	crumbs := folderCrumbs(mount, rel, prefix)
	title := mount.Name()
	if n := len(crumbs); n > 0 {
		title = crumbs[n-1].Name
	}
	data := page{
		Username: user.Username,
		Title:    title,
		Crumbs:   crumbs,
		Rows:     rows,
		ZipURL:   zipURL(mount.ID(), rel),
		HasFiles: hasFiles,
	}
	switch r.URL.Query().Get("err") {
	case "pick":
		data.Error = "Select at least one file."
	case "empty":
		data.Error = "This folder has no files to download."
	case "csrf":
		data.Error = "The form expired. Try again."
	}
	s.render(w, r, http.StatusOK, "browse", data)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, _, resolved, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	if resolved == "" {
		http.NotFound(w, r)
		return
	}
	f, info, err := mount.OpenFile(resolved)
	if err != nil {
		writeFSError(s.Log, w, r, err)
		return
	}
	defer f.Close()
	storage.Serve(w, r, path.Base(resolved), info.ModTime(), f)
}

func (s *Server) downloadZip(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, _, resolved, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	back := browseURL(mount.ID(), resolved)
	if !s.csrfOK(r) {
		http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
		return
	}
	var files []zipFile
	var err error
	if r.PostForm.Get("all") == "1" {
		files, err = folderFiles(mount, user, resolved)
		if err != nil {
			writeFSError(s.Log, w, r, err)
			return
		}
		if len(files) == 0 {
			http.Redirect(w, r, back+"?err=empty", http.StatusSeeOther)
			return
		}
	} else {
		files, ok = selectedFiles(mount, user, resolved, r.PostForm["file"])
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(files) == 0 {
			http.Redirect(w, r, back+"?err=pick", http.StatusSeeOther)
			return
		}
	}
	name := path.Base(resolved)
	if name == "." || name == "/" || name == "" {
		name = mount.Name()
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", storage.ContentDisposition(name+".zip"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private")
	zw := zip.NewWriter(w)
	for _, item := range files {
		if err := writeZipEntry(zw, mount, item); err != nil {
			s.Log.Error("zip", "path", item.rel, "err", err)
			_ = zw.Close()
			return
		}
	}
	if err := zw.Close(); err != nil {
		s.Log.Error("zip close", "err", err)
	}
}

type zipFile struct {
	name string
	rel  string
}

func folderFiles(mount storage.Mount, user auth.User, dir string) ([]zipFile, error) {
	entries, err := mount.List(dir)
	if err != nil {
		return nil, err
	}
	files := make([]zipFile, 0, len(entries))
	for _, ent := range entries {
		rel := ent.Rel
		if ent.IsLink {
			target, err := mount.Canonical(ent.Rel)
			if err != nil || ent.IsDir || ent.Broken || !user.Allows(mount.ID(), target, auth.PermRead) {
				continue
			}
			rel = target
		} else if ent.IsDir {
			continue
		}
		if !user.Allows(mount.ID(), rel, auth.PermRead) {
			continue
		}
		files = append(files, zipFile{name: ent.Name, rel: rel})
	}
	return files, nil
}

func selectedFiles(mount storage.Mount, user auth.User, dir string, names []string) ([]zipFile, bool) {
	if len(names) == 0 {
		return nil, true
	}
	seen := make(map[string]struct{}, len(names))
	files := make([]zipFile, 0, len(names))
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) || strings.ContainsAny(name, "/\\") {
			return nil, false
		}
		joined := name
		if dir != "" {
			joined = dir + "/" + name
		}
		cleaned, err := relpath.Clean(joined)
		if err != nil || path.Base(cleaned) != name {
			return nil, false
		}
		parent := path.Dir(cleaned)
		if parent == "." {
			parent = ""
		}
		if parent != dir {
			return nil, false
		}
		resolved, err := mount.Canonical(cleaned)
		if err != nil || !user.Allows(mount.ID(), resolved, auth.PermRead) {
			return nil, false
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		f, _, err := mount.OpenFile(resolved)
		if err != nil {
			return nil, false
		}
		f.Close()
		seen[resolved] = struct{}{}
		files = append(files, zipFile{name: name, rel: resolved})
	}
	return files, true
}

func writeZipEntry(zw *zip.Writer, mount storage.Mount, item zipFile) error {
	f, info, err := mount.OpenFile(item.rel)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	hdr.Name = item.name
	hdr.Method = zip.Store
	dst, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, f)
	return err
}

func (s *Server) permit(w http.ResponseWriter, r *http.Request, user auth.User, perm auth.Perm) (storage.Mount, string, string, bool) {
	id := r.PathValue("mount")
	mount, ok := s.Portal.Get(id)
	if !ok {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	rel, err := relpath.Clean(r.PathValue("path"))
	if err != nil || !user.Allows(id, rel, perm) {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	resolved, err := mount.Canonical(rel)
	if err != nil || !user.Allows(id, resolved, perm) {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	return mount, rel, resolved, true
}

func (s *Server) entryPoints(user auth.User) []mountLink {
	if user.Role == auth.RoleAdmin {
		mounts := s.Portal.Mounts()
		links := make([]mountLink, 0, len(mounts))
		for _, mount := range mounts {
			links = append(links, mountLink{Name: mount.Name(), Href: browseURL(mount.ID(), "")})
		}
		return links
	}
	var links []mountLink
	for _, scope := range user.Scopes {
		if !scope.Read {
			continue
		}
		mount, ok := s.Portal.Get(scope.MountID)
		if !ok {
			continue
		}
		cleaned, err := relpath.Clean(scope.Path)
		if err != nil {
			continue
		}
		link := mountLink{Name: mount.Name(), Href: browseURL(mount.ID(), cleaned)}
		if cleaned != "" {
			link.Detail = cleaned
		}
		links = append(links, link)
	}
	return links
}

func readPrefix(user auth.User, mountID, rel string) (string, bool) {
	if user.Role == auth.RoleAdmin {
		return "", true
	}
	best := ""
	found := false
	for _, scope := range user.Scopes {
		if scope.MountID != mountID || !scope.Read {
			continue
		}
		cleaned, err := relpath.Clean(scope.Path)
		if err != nil || !relpath.Within(cleaned, rel) {
			continue
		}
		if !found || len(cleaned) > len(best) {
			best = cleaned
			found = true
		}
	}
	return best, found
}

func folderCrumbs(mount storage.Mount, rel, prefix string) []crumb {
	label := mount.Name()
	if prefix != "" {
		label = path.Base(prefix)
	}
	out := []crumb{{Name: label, Href: browseURL(mount.ID(), prefix)}}
	rest := rel
	if prefix != "" {
		if rel == prefix {
			return out
		}
		rest = strings.TrimPrefix(rel, prefix+"/")
	}
	acc := prefix
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" {
			continue
		}
		if acc == "" {
			acc = seg
		} else {
			acc += "/" + seg
		}
		out = append(out, crumb{Name: seg, Href: browseURL(mount.ID(), acc)})
	}
	return out
}

func browseURL(mount, rel string) string   { return fileURL("b", mount, rel) }
func downloadURL(mount, rel string) string { return fileURL("d", mount, rel) }
func zipURL(mount, rel string) string      { return fileURL("z", mount, rel) }

func fileURL(kind, mount, rel string) string {
	var b strings.Builder
	b.WriteByte('/')
	b.WriteString(kind)
	b.WriteByte('/')
	b.WriteString(url.PathEscape(mount))
	if rel == "" {
		return b.String()
	}
	for _, seg := range strings.Split(rel, "/") {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(seg))
	}
	return b.String()
}

func humanSize(n int64) string {
	if n < 0 {
		n = 0
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	size := float64(n)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

func writeFSError(log *slog.Logger, w http.ResponseWriter, r *http.Request, err error) {
	if hiddenFSError(err) {
		http.NotFound(w, r)
		return
	}
	if log != nil {
		log.Error("filesystem", "err", err, "path", r.URL.Path)
	}
	http.Error(w, "something went wrong", http.StatusInternalServerError)
}

func hiddenFSError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, relpath.ErrEscape) ||
		errors.Is(err, relpath.ErrInvalid) ||
		errors.Is(err, storage.ErrNotFile) ||
		errors.Is(err, storage.ErrNotDir) ||
		errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, fs.ErrInvalid) ||
		errors.Is(err, os.ErrInvalid) ||
		errors.Is(err, os.ErrPermission) {
		return true
	}
	return strings.Contains(err.Error(), "escapes")
}
