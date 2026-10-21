package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/tyesamson/vandros-gateway/auth"
)

const csrfCookie = "vandros_csrf"

var settingMessages = map[string]string{
	"brand":    "Branding saved.",
	"reset":    "Branding reset.",
	"colour":   "A colour must look like #0b0c0e.",
	"image":    "Use a PNG, JPG, WEBP, GIF, or ICO under 5 MB.",
	"strength": "Background image strength must be between 0 and 1.",
	"user":     "User created.",
	"password": "Password updated.",
	"role":     "Role updated.",
	"deleted":  "User deleted.",
	"revoked":  "Sessions signed out.",
	"scope":    "Scope added.",
	"unscope":  "Scope removed.",
	"csrf":     "The form expired. Try again.",
	"mismatch": "Those passwords do not match.",
	"invalid":  "That change was not saved. Check the fields and try again.",
}

func (s *Server) settingsGet(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "settings", "users", 0)
}

func (s *Server) settingsBrandGet(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "branding", "brand", 0)
}

func (s *Server) settingsUserGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.renderSettings(w, r, "account", "user", id)
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, tmpl, section string, userID int64) {
	data, err := s.settingsPage(r)
	if err != nil {
		s.Log.Error("settings", "err", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if userID != 0 {
		found := false
		for _, account := range data.Accounts {
			if account.ID == userID {
				data.Focus = account
				found = true
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
	}
	data.Section = section
	switch section {
	case "brand":
		data.Title = "Branding"
	case "user":
		data.Title = data.Focus.Username
	default:
		data.Title = "Users & Scope"
	}
	if msg, ok := settingMessages[r.URL.Query().Get("ok")]; ok {
		data.Notice = msg
	}
	if msg, ok := settingMessages[r.URL.Query().Get("err")]; ok {
		data.Error = msg
	}
	s.render(w, r, http.StatusOK, tmpl, data)
}

func (s *Server) settingsCreateUser(w http.ResponseWriter, r *http.Request) {
	const dest = "/settings"
	if !s.parseForm(w, r) || s.badCSRF(w, r, dest) {
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm") {
		s.settingsErr(w, r, dest, "mismatch")
		return
	}
	mountID := r.PostForm.Get("mount")
	if _, exists := s.Portal.Get(mountID); !exists {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	_, err := s.Users.CreateUser(r.Context(), r.PostForm.Get("username"), password, auth.RoleClient, []auth.Scope{{
		MountID: mountID,
		Path:    r.PostForm.Get("path"),
		Read:    r.PostForm.Get("read") == "on",
		Write:   r.PostForm.Get("write") == "on",
		Delete:  r.PostForm.Get("delete") == "on",
	}})
	if err != nil {
		s.Log.Info("create user", "err", err)
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	s.settingsOK(w, r, dest, "user")
}

func (s *Server) settingsPassword(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dest := userSettingsPath(id)
	if s.badCSRF(w, r, dest) {
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm") {
		s.settingsErr(w, r, dest, "mismatch")
		return
	}
	if err := s.Users.SetPassword(r.Context(), id, password); err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	if err := s.Users.RevokeSessions(r.Context(), id); err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if actor, ok := auth.CurrentUser(r.Context()); ok && actor.ID == id {
		s.clearSession(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.settingsOK(w, r, dest, "password")
}

func (s *Server) settingsRole(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dest := userSettingsPath(id)
	if s.badCSRF(w, r, dest) {
		return
	}
	changed, err := s.Users.SetRole(r.Context(), id, r.PostForm.Get("role"))
	if err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	if changed {
		if err := s.Users.RevokeSessions(r.Context(), id); err != nil {
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		if actor, ok := auth.CurrentUser(r.Context()); ok && actor.ID == id {
			s.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}
	s.settingsOK(w, r, dest, "role")
}

func (s *Server) settingsDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dest := userSettingsPath(id)
	if s.badCSRF(w, r, dest) {
		return
	}
	actor, _ := auth.CurrentUser(r.Context())
	if err := s.Users.DeleteUser(r.Context(), actor.ID, id); err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	s.settingsOK(w, r, "/settings", "deleted")
}

func (s *Server) settingsRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dest := userSettingsPath(id)
	if s.badCSRF(w, r, dest) {
		return
	}
	if err := s.Users.RevokeSessions(r.Context(), id); err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	s.settingsOK(w, r, dest, "revoked")
}

func (s *Server) settingsAddScope(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dest := userSettingsPath(id)
	if s.badCSRF(w, r, dest) {
		return
	}
	mountID := r.PostForm.Get("mount")
	if _, exists := s.Portal.Get(mountID); !exists {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	err := s.Users.AddScope(r.Context(), id, auth.Scope{
		MountID: mountID,
		Path:    r.PostForm.Get("path"),
		Read:    r.PostForm.Get("read") == "on",
		Write:   r.PostForm.Get("write") == "on",
		Delete:  r.PostForm.Get("delete") == "on",
	})
	if err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	s.settingsOK(w, r, dest, "scope")
}

func (s *Server) settingsDeleteScope(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	scopeID, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	userID, err := strconv.ParseInt(r.PostForm.Get("user"), 10, 64)
	dest := "/settings"
	if err == nil && userID > 0 {
		dest = userSettingsPath(userID)
	}
	if s.badCSRF(w, r, dest) {
		return
	}
	if err != nil || userID <= 0 {
		http.NotFound(w, r)
		return
	}
	if err := s.Users.DeleteScope(r.Context(), userID, scopeID); err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	s.settingsOK(w, r, dest, "unscope")
}

func (s *Server) settingsPage(r *http.Request) (page, error) {
	actor, _ := auth.CurrentUser(r.Context())
	users, err := s.Users.ListUsers(r.Context())
	if err != nil {
		return page{}, err
	}
	sessions, err := s.Users.Sessions(r.Context())
	if err != nil {
		return page{}, err
	}
	counts := map[int64]int{}
	for _, item := range sessions {
		counts[item.UserID]++
	}
	accounts := make([]accountView, 0, len(users))
	for _, user := range users {
		account := accountView{
			ID:       user.ID,
			Username: user.Username,
			Role:     user.Role,
			Self:     user.ID == actor.ID,
			Sessions: counts[user.ID],
		}
		for _, scope := range user.Scopes {
			label := scope.MountID
			if scope.Path != "" {
				label += " / " + scope.Path
			} else {
				label += " / entire mount"
			}
			var perms []string
			if scope.Read {
				perms = append(perms, "read")
			}
			if scope.Write {
				perms = append(perms, "write")
			}
			if scope.Delete {
				perms = append(perms, "delete")
			}
			account.Scopes = append(account.Scopes, scopeView{
				ID: scope.ID, User: user.ID, Label: label, Perms: strings.Join(perms, ", "),
			})
		}
		account.ScopeText = scopeSummary(user)
		accounts = append(accounts, account)
	}
	var mounts []mountOption
	for _, mount := range s.Portal.Mounts() {
		mounts = append(mounts, mountOption{ID: mount.ID(), Name: mount.Name()})
	}
	return page{
		Title:        "Settings",
		Accounts:     accounts,
		MountOptions: mounts,
	}, nil
}

func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(s.csrfName()); err == nil && len(cookie.Value) >= 32 {
		return cookie.Value
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := hex.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     s.csrfName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.SecureCookie,
	})
	return token
}

func (s *Server) badCSRF(w http.ResponseWriter, r *http.Request, dest string) bool {
	if s.csrfOK(r) {
		return false
	}
	s.settingsErr(w, r, dest, "csrf")
	return true
}

func (s *Server) csrfOK(r *http.Request) bool {
	cookie, err := r.Cookie(s.csrfName())
	sent := r.PostFormValue("csrf")
	if err != nil || len(sent) != len(cookie.Value) || len(sent) < 32 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sent), []byte(cookie.Value)) == 1
}

func (s *Server) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) settingsOK(w http.ResponseWriter, r *http.Request, dest, code string) {
	http.Redirect(w, r, dest+"?ok="+code, http.StatusSeeOther)
}

func (s *Server) settingsErr(w http.ResponseWriter, r *http.Request, dest, code string) {
	http.Redirect(w, r, dest+"?err="+code, http.StatusSeeOther)
}

func userSettingsPath(id int64) string {
	return "/settings/users/" + strconv.FormatInt(id, 10)
}

func scopeSummary(user auth.User) string {
	if user.Role == auth.RoleAdmin {
		return "All mounts"
	}
	if len(user.Scopes) == 0 {
		return "None"
	}
	parts := make([]string, 0, len(user.Scopes))
	for _, scope := range user.Scopes {
		path := "/"
		if scope.Path != "" {
			path = "/" + scope.Path
		}
		parts = append(parts, scope.MountID+": "+path)
	}
	return strings.Join(parts, ", ")
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
