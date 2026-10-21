package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
)

func (s *Server) loginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.userFromCookie(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", page{})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.csrfOK(r) {
		s.render(w, r, http.StatusForbidden, "login", page{Error: "The form expired. Try again."})
		return
	}
	ip := clientIP(r)
	username := r.PostForm.Get("username")
	account, haveAccount := accountLimitKey(username)
	now := time.Now()
	if s.limit.blocked(ip, now, maxLoginAttempts) || (haveAccount && s.limit.blocked(account, now, maxUserAttempts)) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Error: "Too many attempts. Wait a few minutes."})
		return
	}
	password := r.PostForm.Get("password")
	user, err := s.Users.Authenticate(r.Context(), username, password)
	if err != nil {
		s.limit.fail(ip, now)
		if haveAccount {
			s.limit.fail(account, now)
		}
		if len(username) > 64 || strings.ContainsAny(username, "\r\n") {
			username = "invalid"
		}
		s.Log.Info("login failed", "username", username)
		s.render(w, r, http.StatusUnauthorized, "login", page{Error: "Those credentials were not accepted."})
		return
	}
	token, expires, err := s.Users.CreateSession(r.Context(), user.ID, s.SessionTTL)
	if err != nil {
		s.Log.Error("create session", "err", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	s.limit.reset(ip)
	if haveAccount {
		s.limit.reset(account)
	}
	http.SetCookie(w, s.sessionCookie(token, expires, int(s.SessionTTL.Seconds())))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	if !s.csrfOK(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if cookie, err := r.Cookie(s.sessionCookieName()); err == nil {
		_ = s.Users.DeleteSession(r.Context(), cookie.Value)
	}
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) userFromCookie(r *http.Request) (auth.User, bool) {
	cookie, err := r.Cookie(s.sessionCookieName())
	if err != nil {
		return auth.User{}, false
	}
	user, err := s.Users.UserFromToken(r.Context(), cookie.Value)
	if err != nil {
		return auth.User{}, false
	}
	return user, true
}

func accountLimitKey(username string) (string, bool) {
	if len(username) < 1 || len(username) > 64 {
		return "", false
	}
	for i, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '.' || r == '_' || r == '-') && i > 0:
		default:
			return "", false
		}
	}
	return "user:" + strings.ToLower(username), true
}

func (s *Server) sessionCookieName() string {
	if s.SecureCookie {
		return "__Host-" + auth.CookieName
	}
	return auth.CookieName
}

func (s *Server) csrfName() string {
	if s.SecureCookie {
		return "__Host-" + csrfCookie
	}
	return csrfCookie
}

func (s *Server) sessionCookie(token string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.SecureCookie,
	}
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.SecureCookie,
	})
}
