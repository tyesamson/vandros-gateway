package handlers

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/storage"
)

func TestPortalAccessAndRange(t *testing.T) {
	root := t.TempDir()
	job := filepath.Join(root, "Project_X", "Deliverables")
	if err := os.MkdirAll(job, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte("0123456789reel")
	if err := os.WriteFile(filepath.Join(job, "my reel.mov"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "notes.txt"), []byte("hello notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../secret.txt", filepath.Join(job, "via")); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Parse([]byte("listen: \":8080\"\ndatabase:\n  path: " + filepath.Join(t.TempDir(), "unused.db") + "\nmounts:\n  - id: promise\n    name: Promise\n    path: " + root + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := storage.Open(cfg.Mounts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { portal.Close() })
	users, err := auth.Open(filepath.Join(t.TempDir(), "portal.db"), "test-session-secret-at-least-32-chars")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { users.Close() })
	ctx := t.Context()
	if err := users.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	client, err := users.CreateUser(ctx, "client_abc", "correct-horse-battery", auth.RoleClient, []auth.Scope{{
		MountID: "promise",
		Path:    "Project_X/Deliverables",
		Read:    true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := users.CreateSession(ctx, client.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	app := (&Server{
		Brand:      "The Finish",
		SessionTTL: time.Hour,
		Portal:     portal,
		Users:      users,
	}).Handler()
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	health, err := httpClient.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", health.StatusCode)
	}

	anon, err := httpClient.Get(srv.URL + "/b/promise")
	if err != nil {
		t.Fatal(err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusSeeOther {
		t.Fatalf("anonymous browse = %d", anon.StatusCode)
	}

	secretReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/d/promise/secret.txt", nil)
	secretReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	secretResp, err := httpClient.Do(secretReq)
	if err != nil {
		t.Fatal(err)
	}
	secretBody, _ := io.ReadAll(secretResp.Body)
	secretResp.Body.Close()
	if secretResp.StatusCode != http.StatusNotFound || strings.Contains(string(secretBody), "nope") {
		t.Fatalf("client secret status=%d body=%q", secretResp.StatusCode, secretBody)
	}

	parentReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/b/promise", nil)
	parentReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	parentResp, err := httpClient.Do(parentReq)
	if err != nil {
		t.Fatal(err)
	}
	parentResp.Body.Close()
	if parentResp.StatusCode != http.StatusNotFound {
		t.Fatalf("client parent listing = %d", parentResp.StatusCode)
	}

	fileURL := srv.URL + "/d/promise/Project_X/Deliverables/my%20reel.mov"
	rangeReq, _ := http.NewRequest(http.MethodGet, fileURL, nil)
	rangeReq.Header.Set("Range", "bytes=0-3")
	rangeReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rangeResp, err := httpClient.Do(rangeReq)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rangeResp.Body)
	rangeResp.Body.Close()
	if rangeResp.StatusCode != http.StatusPartialContent || string(got) != "0123" {
		t.Fatalf("range status=%d body=%q", rangeResp.StatusCode, got)
	}
	if rangeResp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content type = %s", rangeResp.Header.Get("Content-Type"))
	}
	if !strings.Contains(rangeResp.Header.Get("Content-Disposition"), "my reel.mov") {
		t.Fatalf("disposition = %s", rangeResp.Header.Get("Content-Disposition"))
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/b/promise/Project_X/Deliverables", nil)
	listReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	listResp, err := httpClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || !strings.Contains(string(page), "my reel.mov") || strings.Contains(string(page), "secret.txt") || strings.Contains(string(page), "via") {
		t.Fatalf("listing status=%d body=%s", listResp.StatusCode, page)
	}
	csrf := csrfFrom(t, listResp, string(page))
	zipBody := postZip(t, httpClient, srv.URL+"/z/promise/Project_X/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"file": {"my reel.mov"},
	})
	names := zipNames(t, zipBody)
	if len(names) != 1 || names["my reel.mov"] != string(payload) {
		t.Fatalf("selected zip = %#v", names)
	}
	escaped := postZipStatus(t, httpClient, srv.URL+"/z/promise/Project_X/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"file": {"../../secret.txt"},
	})
	if escaped != http.StatusNotFound {
		t.Fatalf("zip escape = %d", escaped)
	}
	allBody := postZip(t, httpClient, srv.URL+"/z/promise/Project_X/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"all":  {"1"},
	})
	allNames := zipNames(t, allBody)
	if allNames["my reel.mov"] != string(payload) || allNames["notes.txt"] != "hello notes" || len(allNames) != 2 {
		t.Fatalf("download all = %#v", allNames)
	}

	viaReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/d/promise/Project_X/Deliverables/via", nil)
	viaReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	viaResp, err := httpClient.Do(viaReq)
	if err != nil {
		t.Fatal(err)
	}
	viaBody, _ := io.ReadAll(viaResp.Body)
	viaResp.Body.Close()
	if viaResp.StatusCode != http.StatusNotFound || strings.Contains(string(viaBody), "nope") {
		t.Fatalf("symlink escape status=%d body=%q", viaResp.StatusCode, viaBody)
	}

	loginPage, err := httpClient.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(loginPage.Body)
	loginPage.Body.Close()
	loginCSRF := csrfFrom(t, loginPage, string(loginBody))
	form := url.Values{"username": {"admin"}, "password": {"wrong-horse-battery"}, "csrf": {loginCSRF}}
	badReq, err := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range loginPage.Cookies() {
		if cookie.Name == csrfCookie {
			badReq.AddCookie(cookie)
		}
	}
	bad, err := httpClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", bad.StatusCode)
	}
	naked := url.Values{"username": {"admin"}, "password": {"wrong-horse-battery"}}
	missing, err := httpClient.PostForm(srv.URL+"/login", naked)
	if err != nil {
		t.Fatal(err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusForbidden {
		t.Fatalf("login without csrf = %d", missing.StatusCode)
	}
}

func postZip(t *testing.T, client *http.Client, rawURL, session, csrf string, form url.Values) []byte {
	t.Helper()
	resp := postZipResponse(t, client, rawURL, session, csrf, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zip status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/zip" {
		t.Fatalf("zip type = %s", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postZipStatus(t *testing.T, client *http.Client, rawURL, session, csrf string, form url.Values) int {
	t.Helper()
	resp := postZipResponse(t, client, rawURL, session, csrf, form)
	resp.Body.Close()
	return resp.StatusCode
}

func postZipResponse(t *testing.T, client *http.Client, rawURL, session, csrf string, form url.Values) *http.Response {
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
	return resp
}

func zipNames(t *testing.T, body []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, file := range zr.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[file.Name] = string(data)
	}
	return out
}
