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
	ip := clientIP(r)
	if s.limit.blocked(ip, time.Now()) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Error: "Too many attempts. Wait a few minutes."})
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	user, err := s.Users.Authenticate(r.Context(), username, password)
	if err != nil {
		s.limit.fail(ip, time.Now())
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
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.SessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.SecureCookie,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	if !csrfOK(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if cookie, err := r.Cookie(auth.CookieName); err == nil {
		_ = s.Users.DeleteSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.SecureCookie,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) userFromCookie(r *http.Request) (auth.User, bool) {
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil {
		return auth.User{}, false
	}
	user, err := s.Users.UserFromToken(r.Context(), cookie.Value)
	if err != nil {
		return auth.User{}, false
	}
	return user, true
}
