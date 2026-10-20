package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/storage"
)

func TestSettingsAreAdminOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "job"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("database:\n  path: " + filepath.Join(t.TempDir(), "unused.db") + "\nmounts:\n  - id: promise\n    name: Promise\n    path: " + root + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := storage.Open(cfg.Mounts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	data := t.TempDir()
	users, err := auth.Open(filepath.Join(data, "portal.db"), "test-session-secret-at-least-32-chars")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	ctx := t.Context()
	if err := users.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	if err := users.EnsureBranding(ctx, "Vandros Gateway"); err != nil {
		t.Fatal(err)
	}
	client, err := users.CreateUser(ctx, "client_abc", "correct-horse-battery", auth.RoleClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := users.Authenticate(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, _, err := users.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientToken, _, err := users.CreateSession(ctx, client.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&Server{
		Brand:      "Vandros Gateway",
		SessionTTL: time.Hour,
		DataDir:    data,
		Portal:     portal,
		Users:      users,
	}).Handler())
	t.Cleanup(srv.Close)
	clientHTTP := srv.Client()
	clientHTTP.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	denied := getWith(t, clientHTTP, srv.URL+"/settings", clientToken, "")
	if denied.StatusCode != http.StatusNotFound {
		t.Fatalf("client settings = %d", denied.StatusCode)
	}
	denied.Body.Close()

	page := getWith(t, clientHTTP, srv.URL+"/settings", adminToken, "")
	body := readBody(t, page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "New user") || strings.Contains(body, "Save name") {
		t.Fatalf("settings status=%d body=%s", page.StatusCode, body)
	}
	csrf := csrfFrom(t, page, body)

	brand := getWith(t, clientHTTP, srv.URL+"/settings/branding", adminToken, csrf)
	brandBody := readBody(t, brand)
	if brand.StatusCode != http.StatusOK || !strings.Contains(brandBody, "Save branding") || !strings.Contains(brandBody, "Reset branding") || strings.Contains(brandBody, "New user") {
		t.Fatalf("branding status=%d body=%s", brand.StatusCode, brandBody)
	}
	colours := url.Values{
		"csrf":               {csrf},
		"name":               {"Portal"},
		"bg":                 {"#0b0c0e"},
		"surface":            {"#141518"},
		"ink":                {"#e6e6dc"},
		"muted":              {"#aaaaa4"},
		"line":               {"#2a2b32"},
		"accent":             {"#112233"},
		"button_text":        {"#e6e6dc"},
		"background_opacity": {"0.4"},
	}
	saved := postForm(t, clientHTTP, srv.URL+"/settings/branding", adminToken, csrf, colours)
	if saved.StatusCode != http.StatusSeeOther {
		t.Fatalf("save branding = %d", saved.StatusCode)
	}
	again := getWith(t, clientHTTP, srv.URL+"/settings/branding", adminToken, csrf)
	againBody := readBody(t, again)
	if !strings.Contains(againBody, "--accent: #112233") || !strings.Contains(againBody, `value="Portal"`) {
		t.Fatalf("theme missing: %s", againBody)
	}

	mismatch := url.Values{
		"csrf":     {csrf},
		"username": {"client_two"},
		"password": {"correct-horse-battery"},
		"confirm":  {"correct-horse-stapler"},
		"mount":    {"promise"},
		"read":     {"on"},
	}
	postForm(t, clientHTTP, srv.URL+"/settings/users", adminToken, csrf, mismatch)

	form := url.Values{
		"csrf":     {csrf},
		"username": {"client_two"},
		"password": {"correct-horse-battery"},
		"confirm":  {"correct-horse-battery"},
		"mount":    {"promise"},
		"path":     {"job"},
		"read":     {"on"},
	}
	resp := postForm(t, clientHTTP, srv.URL+"/settings/users", adminToken, csrf, form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), "/settings?ok=user") {
		t.Fatalf("create user = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	created, err := users.Authenticate(ctx, "client_two", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Scopes) != 1 || created.Scopes[0].MountID != "promise" || created.Scopes[0].Path != "job" || !created.Scopes[0].Read {
		t.Fatalf("scope = %+v", created.Scopes)
	}
	edit := getWith(t, clientHTTP, srv.URL+"/settings/users/"+strconv.FormatInt(created.ID, 10), adminToken, csrf)
	editBody := readBody(t, edit)
	if edit.StatusCode != http.StatusOK || !strings.Contains(editBody, "client_two") || !strings.Contains(editBody, "Add scope") {
		t.Fatalf("edit status=%d body=%s", edit.StatusCode, editBody)
	}
}

func postForm(t *testing.T, client *http.Client, rawURL, session, csrf string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func getWith(t *testing.T, client *http.Client, rawURL, session, csrf string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	}
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func csrfFrom(t *testing.T, resp *http.Response, body string) string {
	t.Helper()
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("csrf field missing")
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("csrf field truncated")
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == csrfCookie && cookie.Value != rest[:j] {
			t.Fatalf("csrf cookie %q != field %q", cookie.Value, rest[:j])
		}
	}
	return rest[:j]
}
