package handlers

import (
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/storage"
	"github.com/tyesamson/vandros-gateway/web"
)

const (
	maxLoginAttempts = 20
	maxUserAttempts  = 10
	loginWindow      = 10 * time.Minute
)

// Server is the HTTP portal.
type Server struct {
	Brand        string
	Logo         []byte
	LogoType     string
	SecureCookie bool
	SessionTTL   time.Duration
	DataDir      string
	Portal       *storage.Portal
	Users        *auth.Store
	Log          *slog.Logger
	limit        attemptLimit
}

// Handler returns the routed application.
func (s *Server) Handler() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	static, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", noListing(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /favicon.svg", s.favicon)
	mux.HandleFunc("GET /brand/{kind}", s.brandAsset)
	mux.HandleFunc("GET /login", s.loginGet)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.require(s.logout))
	mux.HandleFunc("GET /{$}", s.require(s.home))
	mux.HandleFunc("GET /settings", s.requireAdmin(s.settingsGet))
	mux.HandleFunc("GET /settings/branding", s.requireAdmin(s.settingsBrandGet))
	mux.HandleFunc("GET /settings/users/{id}", s.requireAdmin(s.settingsUserGet))
	mux.HandleFunc("POST /settings/branding", s.requireAdmin(s.settingsSaveBrand))
	mux.HandleFunc("POST /settings/branding/reset", s.requireAdmin(s.settingsResetBrand))
	mux.HandleFunc("POST /settings/users", s.requireAdmin(s.settingsCreateUser))
	mux.HandleFunc("POST /settings/users/{id}/password", s.requireAdmin(s.settingsPassword))
	mux.HandleFunc("POST /settings/users/{id}/role", s.requireAdmin(s.settingsRole))
	mux.HandleFunc("POST /settings/users/{id}/delete", s.requireAdmin(s.settingsDeleteUser))
	mux.HandleFunc("POST /settings/users/{id}/revoke", s.requireAdmin(s.settingsRevoke))
	mux.HandleFunc("POST /settings/users/{id}/scopes", s.requireAdmin(s.settingsAddScope))
	mux.HandleFunc("POST /settings/scopes/{id}/delete", s.requireAdmin(s.settingsDeleteScope))
	mux.HandleFunc("GET /b/{mount}", s.require(s.browse))
	mux.HandleFunc("GET /b/{mount}/{path...}", s.require(s.browse))
	mux.HandleFunc("GET /d/{mount}/{path...}", s.require(s.download))
	mux.HandleFunc("HEAD /d/{mount}/{path...}", s.require(s.download))
	mux.HandleFunc("POST /z/{mount}", s.require(s.downloadZip))
	mux.HandleFunc("POST /z/{mount}/{path...}", s.require(s.downloadZip))
	return security(mux, s.SecureCookie)
}

func noListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.sessionCookieName())
		if err != nil {
			s.unauthenticated(w, r)
			return
		}
		user, err := s.Users.UserFromToken(r.Context(), cookie.Value)
		if err != nil {
			s.unauthenticated(w, r)
			return
		}
		next(w, r.WithContext(auth.WithUser(r.Context(), user)))
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.require(func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.CurrentUser(r.Context())
		if !ok || user.Role != auth.RoleAdmin {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	})
}

func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Error(w, "sign in required", http.StatusUnauthorized)
}

func security(next http.Handler, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		if secure {
			w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	// RemoteAddr is the direct peer. Forwarded headers are ignored so a
	// client cannot spoof the login limiter.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type attemptLimit struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *attemptLimit) blocked(key string, now time.Time, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits = ensureHits(l.hits)
	l.sweep(now)
	kept := prune(l.hits[key], now)
	if len(kept) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = kept
	}
	return len(kept) >= max
}

func (l *attemptLimit) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits = ensureHits(l.hits)
	l.sweep(now)
	l.hits[key] = append(prune(l.hits[key], now), now)
}

func (l *attemptLimit) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

func ensureHits(m map[string][]time.Time) map[string][]time.Time {
	if m == nil {
		return make(map[string][]time.Time)
	}
	return m
}

func (l *attemptLimit) sweep(now time.Time) {
	if len(l.hits) < 1024 {
		return
	}
	for key, hits := range l.hits {
		kept := prune(hits, now)
		if len(kept) == 0 {
			delete(l.hits, key)
			continue
		}
		l.hits[key] = kept
	}
}

func prune(in []time.Time, now time.Time) []time.Time {
	out := in[:0]
	for _, ts := range in {
		if now.Sub(ts) < loginWindow {
			out = append(out, ts)
		}
	}
	return out
}

var pageTemplates = template.Must(template.ParseFS(web.Files, "templates/*.html"))

type page struct {
	Brand         string
	LogoURL       string
	Username      string
	IsAdmin       bool
	CSRF          string
	Error         string
	Notice        string
	Title         string
	Crumbs        []crumb
	Mounts        []mountLink
	Rows          []row
	ZipURL        string
	HasFiles      bool
	Accounts      []accountView
	MountOptions  []mountOption
	Section       string
	Focus         accountView
	Theme         template.CSS
	FaviconURL    string
	HasBackground bool
	BackgroundURL string
	BrandForm     brand
}

type accountView struct {
	ID        int64
	Username  string
	Role      string
	Self      bool
	Sessions  int
	Scopes    []scopeView
	ScopeText string
}

type scopeView struct {
	ID    int64
	User  int64
	Label string
	Perms string
}

type mountOption struct {
	ID   string
	Name string
}

type crumb struct {
	Name string
	Href string
}

type mountLink struct {
	Name   string
	Detail string
	Href   string
}

type row struct {
	Name     string
	Href     string
	Download string
	Size     string
	Modified string
	Class    string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data page) {
	s.applyBrand(r.Context(), &data)
	if user, ok := auth.CurrentUser(r.Context()); ok {
		if data.Username == "" {
			data.Username = user.Username
		}
		data.IsAdmin = user.Role == auth.RoleAdmin
	}
	if data.CSRF == "" {
		data.CSRF = s.ensureCSRF(w, r)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, name, data); err != nil {
		s.Log.Error("render", "template", name, "err", err)
	}
}
