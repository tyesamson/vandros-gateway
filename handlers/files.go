package handlers

import (
	"archive/zip"
	"context"
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
	if user.Role != auth.RoleAdmin {
		scopes := s.clientScopes(user)
		if len(scopes) == 1 {
			s.browse(w, r.WithContext(withLocated(r.Context(), scopes[0].mount, scopes[0].path)))
			return
		}
		links := make([]mountLink, 0, len(scopes))
		for _, scope := range scopes {
			name := "Files"
			if scope.key != "" {
				name = scope.key
			}
			links = append(links, mountLink{Name: name, Href: joinPublic(scope.key, "")})
		}
		s.render(w, r, http.StatusOK, "mounts", page{Username: user.Username, Mounts: links})
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
	if user.Role != auth.RoleAdmin {
		if dest, ok := s.publicURL(user, mount.ID(), rel); ok && r.URL.Path != dest {
			if r.URL.RawQuery != "" {
				dest += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
	} else if resolved != rel && user.Allows(mount.ID(), resolved, auth.PermRead) {
		http.Redirect(w, r, browseURL(mount.ID(), resolved), http.StatusTemporaryRedirect)
		return
	}
	if q := r.URL.Query().Get("hidden"); q == "show" || q == "hide" {
		s.setShowHidden(w, q == "show")
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	showHidden := showHidden(r)
	entries, err := mount.List(rel)
	missing := false
	if err != nil {
		if !hiddenFSError(err) {
			writeFSError(s.Log, w, r, err)
			return
		}
		entries = nil
		missing = true
	}
	rows := make([]row, 0, len(entries))
	hasFiles := false
	for _, ent := range entries {
		if !showHidden && hiddenEntry(ent.Name) {
			continue
		}
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
				item.Href = s.pageURL(user, mount.ID(), ent.Rel, false)
				item.Class = "dir"
			} else if !ent.Broken {
				item.Href = s.pageURL(user, mount.ID(), ent.Rel, true)
				item.Download = item.Href
				item.Size = humanSize(ent.Size)
				hasFiles = true
			}
		case ent.IsDir:
			item.Href = s.pageURL(user, mount.ID(), ent.Rel, false)
			item.Class = "dir"
		default:
			item.Href = s.pageURL(user, mount.ID(), ent.Rel, true)
			item.Download = item.Href
			item.Size = humanSize(ent.Size)
			item.CanDelete = user.Allows(mount.ID(), ent.Rel, auth.PermDelete)
			hasFiles = true
		}
		rows = append(rows, item)
	}
	here := s.pageURL(user, mount.ID(), rel, false)
	crumbs := s.pageCrumbs(user, mount, rel)
	title := mount.Name()
	if n := len(crumbs); n > 0 {
		title = crumbs[n-1].Name
	}
	data := page{
		Username:   user.Username,
		Title:      title,
		Crumbs:     crumbs,
		Rows:       rows,
		ZipURL:     s.actionURL(user, mount.ID(), rel, "z"),
		UploadURL:  s.actionURL(user, mount.ID(), rel, "u"),
		DeleteURL:  s.actionURL(user, mount.ID(), rel, "rm"),
		BrowseURL:  here,
		CanWrite:   user.Allows(mount.ID(), resolved, auth.PermWrite),
		HasFiles:   hasFiles,
		ShowHidden: showHidden,
		Missing:    missing,
	}
	switch r.URL.Query().Get("err") {
	case "pick":
		data.Error = "Select at least one file."
	case "empty":
		data.Error = "This folder has no files to download."
	case "csrf":
		data.Error = "The form expired. Try again."
	case "name":
		data.Error = "Choose a file with a plain name."
	case "exists":
		data.Error = "A file with that name is already here."
	case "file":
		data.Error = "Only a normal file can be deleted."
	case "large":
		data.Error = "That file is larger than 1 TiB."
	case "ro":
		data.Error = "The server cannot change files in this folder."
	case "upload":
		data.Error = "The upload did not finish."
	}
	switch r.URL.Query().Get("ok") {
	case "uploaded":
		data.Notice = "Uploaded."
	case "deleted":
		data.Notice = "Deleted."
	}
	s.render(w, r, http.StatusOK, "browse", data)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, rel, resolved, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	if user.Role != auth.RoleAdmin {
		if dest, ok := s.publicURL(user, mount.ID(), rel); ok && r.URL.Path != dest {
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
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
	mount, rel, _, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	back := s.returnURL(user, mount.ID(), rel)
	if !s.csrfOK(r) {
		http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
		return
	}
	var files []zipFile
	var err error
	if r.PostForm.Get("all") == "1" {
		files, err = folderFiles(mount, user, rel, showHidden(r))
		if err != nil {
			writeFSError(s.Log, w, r, err)
			return
		}
		if len(files) == 0 {
			http.Redirect(w, r, back+"?err=empty", http.StatusSeeOther)
			return
		}
	} else {
		files, ok = selectedFiles(mount, user, rel, r.PostForm["file"])
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(files) == 0 {
			http.Redirect(w, r, back+"?err=pick", http.StatusSeeOther)
			return
		}
	}
	name := path.Base(rel)
	if name == "." || name == "/" || name == "" {
		name = mount.Name()
	}
	if user.Role != auth.RoleAdmin {
		if _, inside, ok := s.matchClientScope(user, mount.ID(), rel); ok {
			name = "files"
			if inside != "" {
				name = path.Base(inside)
			}
		}
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

func hiddenEntry(name string) bool {
	return strings.HasPrefix(name, ".")
}

const hiddenCookie = "vandros_hidden"

func showHidden(r *http.Request) bool {
	c, err := r.Cookie(hiddenCookie)
	return err == nil && c.Value == "show"
}

func (s *Server) setShowHidden(w http.ResponseWriter, show bool) {
	value := "hide"
	if show {
		value = "show"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     hiddenCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.SecureCookie,
	})
}

func folderFiles(mount storage.Mount, user auth.User, dir string, showHidden bool) ([]zipFile, error) {
	entries, err := mount.List(dir)
	if err != nil {
		return nil, err
	}
	files := make([]zipFile, 0, len(entries))
	for _, ent := range entries {
		if !showHidden && hiddenEntry(ent.Name) {
			continue
		}
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
		if err != nil || !allowsCanonical(mount, user, mount.ID(), cleaned, resolved, auth.PermRead) {
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
	raw := r.PathValue("path")
	if located, ok := locatedFrom(r.Context()); ok {
		id, raw = located.mount, located.rel
	}
	mount, ok := s.Portal.Get(id)
	if !ok {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	rel, err := relpath.Clean(raw)
	if err != nil || !user.Allows(id, rel, perm) {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	resolved, err := mount.Canonical(rel)
	if err != nil || !allowsCanonical(mount, user, id, rel, resolved, perm) {
		http.NotFound(w, r)
		return storage.Mount{}, "", "", false
	}
	return mount, rel, resolved, true
}

// allowsCanonical reports whether resolved stays inside the real directory of a
// scope that already contains requested. A scope path may itself be a symlink.
func allowsCanonical(mount storage.Mount, user auth.User, mountID, requested, resolved string, perm auth.Perm) bool {
	if user.Role == auth.RoleAdmin {
		return true
	}
	for _, scope := range user.Scopes {
		if scope.MountID != mountID || !scopePermits(scope, perm) {
			continue
		}
		scopePath, err := relpath.Clean(scope.Path)
		if err != nil || !relpath.Within(scopePath, requested) {
			continue
		}
		scopeRoot, err := mount.Canonical(scopePath)
		if err != nil || !relpath.Within(scopeRoot, resolved) {
			continue
		}
		return true
	}
	return false
}

func scopePermits(scope auth.Scope, perm auth.Perm) bool {
	switch perm {
	case auth.PermRead:
		return scope.Read
	case auth.PermWrite:
		return scope.Write
	case auth.PermDelete:
		return scope.Delete
	default:
		return false
	}
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

type locatedPath struct {
	mount string
	rel   string
}

type locatedKey struct{}

func withLocated(ctx context.Context, mount, rel string) context.Context {
	return context.WithValue(ctx, locatedKey{}, locatedPath{mount: mount, rel: rel})
}

func locatedFrom(ctx context.Context) (locatedPath, bool) {
	v, ok := ctx.Value(locatedKey{}).(locatedPath)
	return v, ok
}

type scopeRef struct {
	mount string
	path  string
	key   string
}

// clientScopes is the client's view of each Read grant.
// One grant is the whole site, so its address is / and its name is Files.
// The grant's own folder name is never shown.
func (s *Server) clientScopes(user auth.User) []scopeRef {
	if user.Role == auth.RoleAdmin {
		return nil
	}
	var out []scopeRef
	counts := map[string]int{}
	for _, scope := range user.Scopes {
		if !scope.Read {
			continue
		}
		if _, ok := s.Portal.Get(scope.MountID); !ok {
			continue
		}
		cleaned, err := relpath.Clean(scope.Path)
		if err != nil {
			continue
		}
		base := "files"
		if cleaned != "" {
			base = path.Base(cleaned)
		}
		counts[base]++
		key := base
		if counts[base] > 1 {
			key = fmt.Sprintf("%s-%d", base, counts[base])
		}
		out = append(out, scopeRef{mount: scope.MountID, path: cleaned, key: key})
	}
	if len(out) == 1 {
		out[0].key = ""
	}
	return out
}

func (s *Server) matchClientScope(user auth.User, mountID, full string) (scopeRef, string, bool) {
	full, err := relpath.Clean(full)
	if err != nil {
		return scopeRef{}, "", false
	}
	var best scopeRef
	bestLen := -1
	inside := ""
	found := false
	for _, sc := range s.clientScopes(user) {
		if sc.mount != mountID || !relpath.Within(sc.path, full) || len(sc.path) <= bestLen {
			continue
		}
		rel := full
		if sc.path != "" {
			rel = ""
			if full != sc.path {
				rel = strings.TrimPrefix(full, sc.path+"/")
			}
		}
		best = sc
		bestLen = len(sc.path)
		inside = rel
		found = true
	}
	return best, inside, found
}

func (s *Server) publicURL(user auth.User, mountID, full string) (string, bool) {
	sc, inside, ok := s.matchClientScope(user, mountID, full)
	if !ok {
		return "", false
	}
	return joinPublic(sc.key, inside), true
}

func (s *Server) fromClientPath(user auth.User, public string) (string, string, bool) {
	scopes := s.clientScopes(user)
	if len(scopes) == 0 {
		return "", "", false
	}
	public, err := relpath.Clean(public)
	if err != nil {
		return "", "", false
	}
	if len(scopes) == 1 {
		return scopes[0].mount, joinScope(scopes[0].path, public), true
	}
	if public == "" {
		return "", "", false
	}
	seg, rest, _ := strings.Cut(public, "/")
	for _, sc := range scopes {
		if sc.key == seg {
			return sc.mount, joinScope(sc.path, rest), true
		}
	}
	return "", "", false
}

func (s *Server) clientGet(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok || user.Role == auth.RoleAdmin {
		http.NotFound(w, r)
		return
	}
	mountID, rel, ok := s.fromClientPath(user, r.PathValue("path"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	r = r.WithContext(withLocated(r.Context(), mountID, rel))
	mount, _, resolved, ok := s.permit(w, r, user, auth.PermRead)
	if !ok {
		return
	}
	f, info, err := mount.OpenFile(resolved)
	if err == nil {
		defer f.Close()
		storage.Serve(w, r, path.Base(resolved), info.ModTime(), f)
		return
	}
	if !errors.Is(err, storage.ErrNotFile) && !hiddenFSError(err) {
		writeFSError(s.Log, w, r, err)
		return
	}
	s.browse(w, r)
}

func (s *Server) clientPost(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok || user.Role == auth.RoleAdmin {
		http.NotFound(w, r)
		return
	}
	mountID, rel, ok := s.fromClientPath(user, r.PathValue("path"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	r = r.WithContext(withLocated(r.Context(), mountID, rel))
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		s.upload(w, r)
		return
	}
	if !s.parseForm(w, r) {
		return
	}
	if r.PostForm.Get("op") == "rm" {
		s.remove(w, r)
		return
	}
	s.downloadZip(w, r)
}

func (s *Server) pageURL(user auth.User, mountID, rel string, file bool) string {
	if user.Role != auth.RoleAdmin {
		if u, ok := s.publicURL(user, mountID, rel); ok {
			return u
		}
		return ""
	}
	if file {
		return downloadURL(mountID, rel)
	}
	return browseURL(mountID, rel)
}

func (s *Server) actionURL(user auth.User, mountID, rel, kind string) string {
	if user.Role != auth.RoleAdmin {
		if u, ok := s.publicURL(user, mountID, rel); ok {
			return u
		}
		return "/"
	}
	switch kind {
	case "z":
		return zipURL(mountID, rel)
	case "u":
		return uploadURL(mountID, rel)
	case "rm":
		return deleteURL(mountID, rel)
	default:
		return browseURL(mountID, rel)
	}
}

func (s *Server) returnURL(user auth.User, mountID, rel string) string {
	if user.Role != auth.RoleAdmin {
		if u, ok := s.publicURL(user, mountID, rel); ok {
			return u
		}
		return "/"
	}
	return browseURL(mountID, rel)
}

func (s *Server) pageCrumbs(user auth.User, mount storage.Mount, rel string) []crumb {
	if user.Role == auth.RoleAdmin {
		prefix, _ := readPrefix(user, mount.ID(), rel)
		return folderCrumbs(mount, rel, prefix)
	}
	sc, inside, ok := s.matchClientScope(user, mount.ID(), rel)
	label := "Files"
	href := "/"
	if ok {
		href = joinPublic(sc.key, "")
		if sc.key != "" {
			label = sc.key
		}
	}
	out := []crumb{{Name: label, Href: href}}
	acc := ""
	for _, seg := range strings.Split(inside, "/") {
		if seg == "" {
			continue
		}
		if acc == "" {
			acc = seg
		} else {
			acc += "/" + seg
		}
		out = append(out, crumb{Name: seg, Href: joinPublic(sc.key, acc)})
	}
	return out
}

func joinScope(scope, rest string) string {
	if rest == "" {
		return scope
	}
	if scope == "" {
		return rest
	}
	return scope + "/" + rest
}

func joinPublic(key, rel string) string {
	var parts []string
	if key != "" {
		parts = append(parts, key)
	}
	if rel != "" {
		parts = append(parts, strings.Split(rel, "/")...)
	}
	if len(parts) == 0 {
		return "/"
	}
	var b strings.Builder
	for _, part := range parts {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(part))
	}
	return b.String()
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
func uploadURL(mount, rel string) string   { return fileURL("u", mount, rel) }
func deleteURL(mount, rel string) string   { return fileURL("rm", mount, rel) }

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
