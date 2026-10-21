package handlers

import (
	"crypto/subtle"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/storage"
)

// maxUploadBytes stops one request from writing without limit.
// 1 TiB covers a long high-bitrate master.
const maxUploadBytes = 1 << 40

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, _, resolved, ok := s.permit(w, r, user, auth.PermWrite)
	if !ok {
		return
	}
	back := browseURL(mount.ID(), resolved)
	cookie, err := r.Cookie(s.csrfName())
	if err != nil || len(cookie.Value) < 32 {
		http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		http.Redirect(w, r, back+"?err=upload", http.StatusSeeOther)
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		http.Redirect(w, r, back+"?err=upload", http.StatusSeeOther)
		return
	}
	var token string
	haveToken := false
	wrote := false
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			if wrote {
				break
			}
			http.Redirect(w, r, back+"?err=upload", http.StatusSeeOther)
			return
		}
		switch part.FormName() {
		case "csrf":
			token, err = readPart(part, 128)
			haveToken = err == nil
		case "file":
			if !haveToken || !tokenMatch(cookie.Value, token) {
				part.Close()
				http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
				return
			}
			if wrote {
				part.Close()
				http.Redirect(w, r, back+"?err=upload", http.StatusSeeOther)
				return
			}
			name, ok := uploadName(part.FileName())
			if !ok || !user.Allows(mount.ID(), joinUpload(resolved, name), auth.PermWrite) {
				part.Close()
				http.Redirect(w, r, back+"?err=name", http.StatusSeeOther)
				return
			}
			if err := s.writeUpload(mount, resolved, name, part); err != nil {
				part.Close()
				http.Redirect(w, r, back+"?"+uploadQuery(err), http.StatusSeeOther)
				return
			}
			wrote = true
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, 1<<20))
		}
		part.Close()
	}
	if !haveToken || !tokenMatch(cookie.Value, token) {
		http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
		return
	}
	if !wrote {
		http.Redirect(w, r, back+"?err=name", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?ok=uploaded", http.StatusSeeOther)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	user, ok := auth.CurrentUser(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	mount, _, resolved, ok := s.permit(w, r, user, auth.PermDelete)
	if !ok {
		return
	}
	back := browseURL(mount.ID(), resolved)
	if !s.csrfOK(r) {
		http.Redirect(w, r, back+"?err=csrf", http.StatusSeeOther)
		return
	}
	name, ok := uploadName(r.PostForm.Get("file"))
	rel := joinUpload(resolved, name)
	if !ok || !user.Allows(mount.ID(), rel, auth.PermDelete) {
		http.NotFound(w, r)
		return
	}
	canon, err := mount.Canonical(rel)
	if err != nil || canon != rel {
		http.NotFound(w, r)
		return
	}
	if err := mount.RemoveFile(rel); err != nil {
		if errors.Is(err, storage.ErrNotFile) {
			http.Redirect(w, r, back+"?err=file", http.StatusSeeOther)
			return
		}
		writeFSError(s.Log, w, r, err)
		return
	}
	http.Redirect(w, r, back+"?ok=deleted", http.StatusSeeOther)
}

func (s *Server) writeUpload(mount storage.Mount, dir, name string, part *multipart.Part) error {
	f, err := mount.CreateExclusive(dir, name)
	if err != nil {
		return err
	}
	rel := joinUpload(dir, name)
	n, copyErr := io.Copy(f, io.LimitReader(part, maxUploadBytes+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if n > maxUploadBytes {
		_ = mount.RemoveFile(rel)
		return errTooLarge
	}
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = mount.RemoveFile(rel)
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

var errTooLarge = errors.New("upload exceeds limit")

func uploadQuery(err error) string {
	switch {
	case errors.Is(err, storage.ErrExists):
		return "err=exists"
	case errors.Is(err, errTooLarge):
		return "err=large"
	case errors.Is(err, os.ErrPermission):
		return "err=ro"
	default:
		return "err=upload"
	}
}

func uploadName(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "/\\\x00") || raw != path.Base(raw) {
		return "", false
	}
	if raw == "" || raw == "." || raw == ".." || len(raw) > 255 {
		return "", false
	}
	return raw, true
}

func joinUpload(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func readPart(part *multipart.Part, limit int64) (string, error) {
	b, err := io.ReadAll(io.LimitReader(part, limit))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func tokenMatch(cookie, sent string) bool {
	if len(sent) != len(cookie) || len(sent) < 32 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sent), []byte(cookie)) == 1
}
