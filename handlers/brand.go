package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tyesamson/vandros-gateway/config"
)

const brandSetting = "branding"

var (
	errColour   = errors.New("colour")
	errImage    = errors.New("image")
	errStrength = errors.New("strength")
	hexColour   = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	brandNameRE = regexp.MustCompile(`^(logo|favicon|background)\.(png|jpg|webp|gif|ico|svg)$`)
)

type brand struct {
	Name       string `json:"name"`
	BG         string `json:"bg"`
	Surface    string `json:"surface"`
	Ink        string `json:"ink"`
	Muted      string `json:"muted"`
	Line       string `json:"line"`
	Accent     string `json:"accent"`
	ButtonText string `json:"button_text"`
	Opacity    string `json:"background_opacity"`
	Logo       string `json:"logo"`
	Favicon    string `json:"favicon"`
	Background string `json:"background_image"`
}

func defaultBrand(name string) brand {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Vandros Gateway"
	}
	return brand{
		Name:       name,
		BG:         "#0b0c0e",
		Surface:    "#141518",
		Ink:        "#e6e6dc",
		Muted:      "#aaaaa4",
		Line:       "#2a2b32",
		Accent:     "#a62525",
		ButtonText: "#e6e6dc",
		Opacity:    "0.28",
	}
}

func (s *Server) loadBrand(ctx context.Context) (brand, error) {
	base := defaultBrand(s.Brand)
	raw, ok, err := s.Users.Setting(ctx, brandSetting)
	if err != nil {
		return brand{}, err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		if name, nameOK, nameErr := s.Users.Setting(ctx, "brand_name"); nameErr == nil && nameOK {
			name = strings.TrimSpace(name)
			if name != "" && !strings.ContainsAny(name, "\r\n") && len(name) <= 80 {
				base.Name = name
			}
		}
		if file, fileOK, fileErr := s.Users.Setting(ctx, "logo_file"); fileErr == nil && fileOK && safeBrandFile("logo", file) {
			base.Logo = file
		}
		return base, nil
	}
	var stored brand
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return base, nil
	}
	return base.merge(stored), nil
}

func (base brand) merge(stored brand) brand {
	if name := strings.TrimSpace(stored.Name); name != "" && !strings.ContainsAny(name, "\r\n") && len(name) <= 80 {
		base.Name = name
	}
	set := func(dst *string, value, fallback string) {
		if colour, err := normalizeHex(value); err == nil {
			*dst = colour
			return
		}
		*dst = fallback
	}
	set(&base.BG, stored.BG, base.BG)
	set(&base.Surface, stored.Surface, base.Surface)
	set(&base.Ink, stored.Ink, base.Ink)
	set(&base.Muted, stored.Muted, base.Muted)
	set(&base.Line, stored.Line, base.Line)
	set(&base.Accent, stored.Accent, base.Accent)
	set(&base.ButtonText, stored.ButtonText, base.ButtonText)
	if opacity, err := normalizeOpacity(stored.Opacity); err == nil {
		base.Opacity = opacity
	}
	if safeBrandFile("logo", stored.Logo) {
		base.Logo = stored.Logo
	}
	if safeBrandFile("favicon", stored.Favicon) {
		base.Favicon = stored.Favicon
	}
	if safeBrandFile("background", stored.Background) {
		base.Background = stored.Background
	}
	return base
}

func (b brand) css() template.CSS {
	var buf strings.Builder
	fmt.Fprintf(&buf, "--bg: %s; --surface: %s; --ink: %s; --muted: %s; --line: %s; --accent: %s; --button-text: %s; --bg-image-opacity: %s;",
		b.BG, b.Surface, b.Ink, b.Muted, b.Line, b.Accent, b.ButtonText, b.Opacity)
	if b.Background != "" {
		buf.WriteString(" --bg-image: url('/brand/background');")
	}
	return template.CSS(buf.String())
}

func (s *Server) saveBrand(ctx context.Context, b brand) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.Users.SetSetting(ctx, brandSetting, string(raw))
}

func (s *Server) settingsSaveBrand(w http.ResponseWriter, r *http.Request) {
	const dest = "/settings/branding"
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		err = r.ParseMultipartForm(16 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		s.settingsErr(w, r, dest, "invalid")
		return
	}
	if s.badCSRF(w, r, dest) {
		return
	}
	current, err := s.loadBrand(r.Context())
	if err != nil {
		s.Log.Error("brand", "err", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	next, err := s.brandFromForm(current, r)
	if err != nil {
		switch {
		case errors.Is(err, errColour):
			s.settingsErr(w, r, dest, "colour")
		case errors.Is(err, errImage):
			s.settingsErr(w, r, dest, "image")
		case errors.Is(err, errStrength):
			s.settingsErr(w, r, dest, "strength")
		default:
			s.Log.Error("brand", "err", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
		}
		return
	}
	if err := s.saveBrand(r.Context(), next); err != nil {
		s.Log.Error("brand", "err", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	s.settingsOK(w, r, dest, "brand")
}

func (s *Server) settingsResetBrand(w http.ResponseWriter, r *http.Request) {
	const dest = "/settings/branding"
	if !s.parseForm(w, r) || s.badCSRF(w, r, dest) {
		return
	}
	if err := s.saveBrand(r.Context(), defaultBrand(s.Brand)); err != nil {
		s.Log.Error("brand reset", "err", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	s.clearBrandFiles()
	_ = s.Users.ClearSetting(r.Context(), "logo_file")
	_ = s.Users.ClearSetting(r.Context(), "logo_type")
	s.settingsOK(w, r, dest, "reset")
}

func (s *Server) brandFromForm(current brand, r *http.Request) (brand, error) {
	next := current
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		name = defaultBrand("").Name
	}
	if len(name) > 80 || strings.ContainsAny(name, "\r\n") {
		return brand{}, errors.New("name")
	}
	next.Name = name
	colours := []struct {
		field string
		dst   *string
	}{
		{"bg", &next.BG},
		{"surface", &next.Surface},
		{"ink", &next.Ink},
		{"muted", &next.Muted},
		{"line", &next.Line},
		{"accent", &next.Accent},
		{"button_text", &next.ButtonText},
	}
	for _, item := range colours {
		value, err := normalizeHex(r.PostForm.Get(item.field))
		if err != nil {
			return brand{}, errColour
		}
		*item.dst = value
	}
	opacity, err := normalizeOpacity(r.PostForm.Get("background_opacity"))
	if err != nil {
		return brand{}, errStrength
	}
	next.Opacity = opacity
	files := []struct {
		field    string
		dst      *string
		allowICO bool
	}{
		{"logo", &next.Logo, true},
		{"favicon", &next.Favicon, true},
		{"background_image", &next.Background, false},
	}
	for _, item := range files {
		file, header, err := r.FormFile(item.field)
		if err != nil {
			continue
		}
		name, err := s.storeBrandFile(item.field, file, header, item.allowICO)
		file.Close()
		if err != nil {
			return brand{}, err
		}
		*item.dst = name
	}
	if r.PostForm.Get("remove_logo") != "" {
		next.Logo = ""
		s.deleteBrandKind("logo")
	}
	if r.PostForm.Get("remove_favicon") != "" {
		next.Favicon = ""
		s.deleteBrandKind("favicon")
	}
	if r.PostForm.Get("remove_background") != "" {
		next.Background = ""
		s.deleteBrandKind("background")
	}
	return next, nil
}

func normalizeHex(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if !hexColour.MatchString(raw) {
		return "", errColour
	}
	if len(raw) == 4 {
		raw = "#" + strings.Repeat(string(raw[1]), 2) + strings.Repeat(string(raw[2]), 2) + strings.Repeat(string(raw[3]), 2)
	}
	return strings.ToLower(raw), nil
}

func normalizeOpacity(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "0.28", nil
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || n < 0 || n > 1 {
		return "", errStrength
	}
	return strconv.FormatFloat(n, 'f', -1, 64), nil
}

func safeBrandFile(kind, name string) bool {
	return brandNameRE.MatchString(name) && strings.HasPrefix(name, kind+".")
}

func (s *Server) brandAsset(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "logo" && kind != "favicon" && kind != "background" {
		http.NotFound(w, r)
		return
	}
	b, err := s.loadBrand(r.Context())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := map[string]string{"logo": b.Logo, "favicon": b.Favicon, "background": b.Background}[kind]
	if kind == "logo" && name == "" && len(s.Logo) > 0 {
		writeImage(w, s.LogoType, s.Logo)
		return
	}
	if !safeBrandFile(kind, name) {
		http.NotFound(w, r)
		return
	}
	body, err := os.ReadFile(filepath.Join(s.DataDir, "branding", name))
	if err != nil || len(body) == 0 || len(body) > 5<<20 {
		http.NotFound(w, r)
		return
	}
	writeImage(w, imageType(name), body)
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	b, err := s.loadBrand(r.Context())
	if err != nil {
		b = defaultBrand(s.Brand)
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="%s"/><path d="M8 20c4-10 12-10 16 0" fill="none" stroke="%s" stroke-width="2.4" stroke-linecap="round"/><circle cx="22.5" cy="11" r="2" fill="%s"/></svg>`, b.BG, b.Accent, b.Ink)
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write([]byte(svg))
}

func writeImage(w http.ResponseWriter, ctype string, body []byte) {
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=300")
	if ctype == "image/svg+xml" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	}
	_, _ = w.Write(body)
}

func imageType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

func (s *Server) storeBrandFile(field string, file multipart.File, _ *multipart.FileHeader, allowICO bool) (string, error) {
	dir := filepath.Join(s.DataDir, "branding")
	body, err := io.ReadAll(io.LimitReader(file, 5<<20+1))
	if err != nil || len(body) == 0 || len(body) > 5<<20 {
		return "", errImage
	}
	ext := sniffImage(body)
	if ext == "" || (ext == ".ico" && !allowICO) {
		return "", errImage
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	name := field + ext
	if field == "background_image" {
		name = "background" + ext
	}
	temp, err := os.CreateTemp(dir, field+"-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	_, writeErr := temp.Write(body)
	closeErr := temp.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(tempName)
		return "", errors.Join(writeErr, closeErr)
	}
	if err := os.Rename(tempName, filepath.Join(dir, name)); err != nil {
		os.Remove(tempName)
		return "", err
	}
	for _, old := range []string{".png", ".jpg", ".webp", ".gif", ".ico", ".svg"} {
		if old == ext {
			continue
		}
		os.Remove(filepath.Join(dir, strings.TrimSuffix(name, ext)+old))
	}
	return name, nil
}

func sniffImage(data []byte) string {
	return config.ImageExtension(data)
}

func (s *Server) clearBrandFiles() {
	for _, kind := range []string{"logo", "favicon", "background"} {
		s.deleteBrandKind(kind)
	}
}

func (s *Server) deleteBrandKind(kind string) {
	dir := filepath.Join(s.DataDir, "branding")
	for _, ext := range []string{".png", ".jpg", ".webp", ".gif", ".ico", ".svg"} {
		os.Remove(filepath.Join(dir, kind+ext))
	}
}

func (s *Server) applyBrand(ctx context.Context, data *page) {
	b, err := s.loadBrand(ctx)
	if err != nil {
		s.Log.Error("brand", "err", err)
		b = defaultBrand(s.Brand)
	}
	data.Brand = b.Name
	data.Theme = b.css()
	data.HasBackground = b.Background != ""
	data.BrandForm = b
	if b.Favicon != "" {
		data.FaviconURL = "/brand/favicon"
	}
	if b.Logo != "" || len(s.Logo) > 0 {
		data.LogoURL = "/brand/logo"
	}
	if b.Background != "" {
		data.BackgroundURL = "/brand/background"
	}
}
