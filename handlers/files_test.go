package handlers

import (
	"archive/zip"
	"bytes"
	"io"
	"mime/multipart"
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
	job := filepath.Join(root, "client", "Deliverables")
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

	cfg, err := config.Parse([]byte("listen: \":24731\"\ndatabase:\n  path: " + filepath.Join(t.TempDir(), "unused.db") + "\nmounts:\n  - id: library\n    name: Library\n    path: " + root + "\n"))
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
		MountID: "library",
		Path:    "client/Deliverables",
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

	anon, err := httpClient.Get(srv.URL + "/b/library")
	if err != nil {
		t.Fatal(err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusSeeOther {
		t.Fatalf("anonymous browse = %d", anon.StatusCode)
	}

	secretReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/d/library/secret.txt", nil)
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

	parentReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/b/library", nil)
	parentReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	parentResp, err := httpClient.Do(parentReq)
	if err != nil {
		t.Fatal(err)
	}
	parentResp.Body.Close()
	if parentResp.StatusCode != http.StatusNotFound {
		t.Fatalf("client parent listing = %d", parentResp.StatusCode)
	}

	fileURL := srv.URL + "/d/library/client/Deliverables/my%20reel.mov"
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

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/b/library/client/Deliverables", nil)
	listReq.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	listResp, err := httpClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || !strings.Contains(string(page), "my reel.mov") || strings.Contains(string(page), "secret.txt") || strings.Contains(string(page), "via") || strings.Contains(string(page), "Upload") || strings.Contains(string(page), "Delete") {
		t.Fatalf("listing status=%d body=%s", listResp.StatusCode, page)
	}
	csrf := csrfFrom(t, listResp, string(page))
	zipBody := postZip(t, httpClient, srv.URL+"/z/library/client/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"file": {"my reel.mov"},
	})
	names := zipNames(t, zipBody)
	if len(names) != 1 || names["my reel.mov"] != string(payload) {
		t.Fatalf("selected zip = %#v", names)
	}
	escaped := postZipStatus(t, httpClient, srv.URL+"/z/library/client/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"file": {"../../secret.txt"},
	})
	if escaped != http.StatusNotFound {
		t.Fatalf("zip escape = %d", escaped)
	}
	allBody := postZip(t, httpClient, srv.URL+"/z/library/client/Deliverables", token, csrf, url.Values{
		"csrf": {csrf},
		"all":  {"1"},
	})
	allNames := zipNames(t, allBody)
	if allNames["my reel.mov"] != string(payload) || allNames["notes.txt"] != "hello notes" || len(allNames) != 2 {
		t.Fatalf("download all = %#v", allNames)
	}

	viaReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/d/library/client/Deliverables/via", nil)
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

func TestUploadAndDelete(t *testing.T) {
	root := t.TempDir()
	job := filepath.Join(root, "client", "inbox")
	if err := os.MkdirAll(job, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(job, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("notes.txt", filepath.Join(job, "link")); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Parse([]byte("listen: \":24731\"\ndatabase:\n  path: " + filepath.Join(t.TempDir(), "unused.db") + "\nmounts:\n  - id: library\n    name: Library\n    path: " + root + "\n"))
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
	admin, err := users.Authenticate(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, _, err := users.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := users.CreateUser(ctx, "reader", "correct-horse-battery", auth.RoleClient, []auth.Scope{{
		MountID: "library", Path: "client/inbox", Read: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := users.CreateUser(ctx, "writer", "correct-horse-battery", auth.RoleClient, []auth.Scope{{
		MountID: "library", Path: "client/inbox", Read: true, Write: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	remover, err := users.CreateUser(ctx, "remover", "correct-horse-battery", auth.RoleClient, []auth.Scope{{
		MountID: "library", Path: "client/inbox", Read: true, Delete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	readerToken, _, err := users.CreateSession(ctx, reader.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writerToken, _, err := users.CreateSession(ctx, writer.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	removerToken, _, err := users.CreateSession(ctx, remover.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	app := (&Server{Brand: "The Finish", SessionTTL: time.Hour, Portal: portal, Users: users}).Handler()
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	folder := srv.URL + "/b/library/client/inbox"
	adminCSRF := csrfFor(t, httpClient, folder, adminToken)
	writerCSRF := csrfFor(t, httpClient, folder, writerToken)

	if status := uploadStatus(t, httpClient, srv.URL+"/u/library/client/inbox", readerToken, adminCSRF, "drop.txt", "hello", true); status != http.StatusNotFound {
		t.Fatalf("reader upload = %d", status)
	}
	if status := uploadStatus(t, httpClient, srv.URL+"/u/library", writerToken, writerCSRF, "drop.txt", "hello", true); status != http.StatusNotFound {
		t.Fatalf("writer parent upload = %d", status)
	}
	if status := uploadStatus(t, httpClient, srv.URL+"/u/library/client/inbox", writerToken, writerCSRF, "../secret.txt", "x", true); status != http.StatusSeeOther {
		t.Fatalf("bad name status = %d", status)
	}
	if _, err := os.Stat(filepath.Join(root, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	secret, err := os.ReadFile(filepath.Join(root, "secret.txt"))
	if err != nil || string(secret) != "nope" {
		t.Fatalf("secret changed: %q %v", secret, err)
	}
	if status := uploadStatus(t, httpClient, srv.URL+"/u/library/client/inbox", writerToken, writerCSRF, "drop.txt", "hello", false); status != http.StatusSeeOther {
		t.Fatalf("file before csrf = %d", status)
	}
	if _, err := os.Stat(filepath.Join(job, "drop.txt")); !os.IsNotExist(err) {
		t.Fatalf("early file part was stored: %v", err)
	}
	if status := uploadStatus(t, httpClient, srv.URL+"/u/library/client/inbox", writerToken, writerCSRF, "drop.txt", "hello", true); status != http.StatusSeeOther {
		t.Fatalf("writer upload = %d", status)
	}
	body, err := os.ReadFile(filepath.Join(job, "drop.txt"))
	if err != nil || string(body) != "hello" {
		t.Fatalf("uploaded = %q %v", body, err)
	}
	if status := uploadStatus(t, httpClient, srv.URL+"/u/library/client/inbox", writerToken, writerCSRF, "drop.txt", "again", true); status != http.StatusSeeOther {
		t.Fatalf("overwrite status = %d", status)
	}
	body, err = os.ReadFile(filepath.Join(job, "drop.txt"))
	if err != nil || string(body) != "hello" {
		t.Fatalf("overwrite changed file: %q %v", body, err)
	}

	if status := deleteStatus(t, httpClient, srv.URL+"/rm/library/client/inbox", writerToken, writerCSRF, "drop.txt"); status != http.StatusNotFound {
		t.Fatalf("writer delete = %d", status)
	}
	if _, err := os.Stat(filepath.Join(job, "drop.txt")); err != nil {
		t.Fatal(err)
	}
	if status := deleteStatus(t, httpClient, srv.URL+"/rm/library/client/inbox", removerToken, csrfFor(t, httpClient, folder, removerToken), "folder"); status != http.StatusSeeOther {
		t.Fatalf("directory delete = %d", status)
	}
	if _, err := os.Stat(filepath.Join(job, "folder")); err != nil {
		t.Fatalf("directory removed: %v", err)
	}
	if status := deleteStatus(t, httpClient, srv.URL+"/rm/library/client/inbox", removerToken, csrfFor(t, httpClient, folder, removerToken), "link"); status != http.StatusNotFound {
		t.Fatalf("symlink delete = %d", status)
	}
	if _, err := os.Lstat(filepath.Join(job, "link")); err != nil {
		t.Fatalf("symlink removed: %v", err)
	}
	if status := deleteStatus(t, httpClient, srv.URL+"/rm/library/client/inbox", removerToken, csrfFor(t, httpClient, folder, removerToken), "drop.txt"); status != http.StatusSeeOther {
		t.Fatalf("remover delete = %d", status)
	}
	if _, err := os.Stat(filepath.Join(job, "drop.txt")); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}

	if status := uploadStatus(t, httpClient, srv.URL+"/u/library", adminToken, adminCSRF, "root.txt", "admin", true); status != http.StatusSeeOther {
		t.Fatalf("admin upload = %d", status)
	}
	if status := deleteStatus(t, httpClient, srv.URL+"/rm/library", adminToken, adminCSRF, "secret.txt"); status != http.StatusSeeOther {
		t.Fatalf("admin delete = %d", status)
	}
	if _, err := os.Stat(filepath.Join(root, "secret.txt")); !os.IsNotExist(err) {
		t.Fatalf("admin left secret: %v", err)
	}
	page, _ := fetchPage(t, httpClient, folder, adminToken)
	if !strings.Contains(page, "data-upload") || !strings.Contains(page, "Delete") {
		t.Fatalf("admin controls missing: %s", page)
	}
}

func csrfFor(t *testing.T, client *http.Client, rawURL, session string) string {
	t.Helper()
	_, token := fetchPage(t, client, rawURL, session)
	return token
}

func fetchPage(t *testing.T, client *http.Client, rawURL, session string) (string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", rawURL, resp.StatusCode)
	}
	return string(body), csrfFrom(t, resp, string(body))
}

func uploadStatus(t *testing.T, client *http.Client, rawURL, session, csrf, name, contents string, tokenFirst bool) int {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if tokenFirst {
		if err := w.WriteField("csrf", csrf); err != nil {
			t.Fatal(err)
		}
	}
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if !tokenFirst {
		if err := w.WriteField("csrf", csrf); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func deleteStatus(t *testing.T, client *http.Client, rawURL, session, csrf, name string) int {
	t.Helper()
	form := url.Values{"csrf": {csrf}, "file": {name}}
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
	return resp.StatusCode
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
