package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	minSessionTTL = time.Minute
	maxSessionTTL = 30 * 24 * time.Hour
	maxLogoBytes  = 2 << 20
)

var mountIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// Config is the process configuration. User accounts, permissions, and
// share links are stored in SQLite, not here.
type Config struct {
	Listen       string
	SessionTTL   time.Duration
	SecureCookie bool
	DatabasePath string
	BrandName    string
	LogoPath     string
	Mounts       []Mount
}

// Mount is one host directory exposed as a top-level root.
type Mount struct {
	ID   string
	Name string
	Path string
}

type file struct {
	Listen   string      `yaml:"listen"`
	Session  session     `yaml:"session"`
	Database database    `yaml:"database"`
	Branding branding    `yaml:"branding"`
	Mounts   []mountFile `yaml:"mounts"`
}

type session struct {
	TTL    string `yaml:"ttl"`
	Secure bool   `yaml:"secure"`
}

type database struct {
	Path string `yaml:"path"`
}

type branding struct {
	Name string `yaml:"name"`
	Logo string `yaml:"logo"`
}

type mountFile struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// Load reads path and checks that every mount is a real directory.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(b)
}

// Parse validates raw YAML. Mount paths must already exist.
func Parse(b []byte) (Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var raw file
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return raw.config()
}

func (raw file) config() (Config, error) {
	listen := raw.Listen
	if listen == "" {
		listen = ":24731"
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return Config{}, fmt.Errorf("listen: %w", err)
	}

	ttl := 12 * time.Hour
	if raw.Session.TTL != "" {
		d, err := time.ParseDuration(raw.Session.TTL)
		if err != nil {
			return Config{}, fmt.Errorf("session.ttl: %w", err)
		}
		if d < minSessionTTL || d > maxSessionTTL {
			return Config{}, fmt.Errorf("session.ttl must be between %s and %s", minSessionTTL, maxSessionTTL)
		}
		ttl = d
	}

	if strings.TrimSpace(raw.Database.Path) == "" {
		return Config{}, errors.New("database.path is required")
	}
	dbPath, err := filepath.Abs(raw.Database.Path)
	if err != nil {
		return Config{}, fmt.Errorf("database.path: %w", err)
	}

	brand := strings.TrimSpace(raw.Branding.Name)
	if brand == "" {
		brand = "Vandros Gateway"
	}
	logo := strings.TrimSpace(raw.Branding.Logo)
	if logo != "" {
		logo, err = filepath.Abs(logo)
		if err != nil {
			return Config{}, fmt.Errorf("branding.logo: %w", err)
		}
		if err := checkLogo(logo); err != nil {
			return Config{}, fmt.Errorf("branding.logo: %w", err)
		}
	}

	if len(raw.Mounts) == 0 {
		return Config{}, errors.New("at least one mount is required")
	}
	seenID := make(map[string]struct{}, len(raw.Mounts))
	var mounts []Mount
	var roots []string
	for _, m := range raw.Mounts {
		if !mountIDPattern.MatchString(m.ID) {
			return Config{}, fmt.Errorf("mount id %q must match %s", m.ID, mountIDPattern)
		}
		if _, ok := seenID[m.ID]; ok {
			return Config{}, fmt.Errorf("duplicate mount id %q", m.ID)
		}
		seenID[m.ID] = struct{}{}
		name := strings.TrimSpace(m.Name)
		if name == "" || len(name) > 64 {
			return Config{}, fmt.Errorf("mount %s: name is required and must be at most 64 characters", m.ID)
		}
		if !filepath.IsAbs(m.Path) {
			return Config{}, fmt.Errorf("mount %s: path must be absolute", m.ID)
		}
		resolved, err := resolveDir(m.Path)
		if err != nil {
			return Config{}, fmt.Errorf("mount %s: %w", m.ID, err)
		}
		for _, other := range roots {
			if sameOrNested(resolved, other) {
				return Config{}, fmt.Errorf("mount %s: path overlaps another mount", m.ID)
			}
		}
		roots = append(roots, resolved)
		mounts = append(mounts, Mount{ID: m.ID, Name: name, Path: resolved})
	}

	return Config{
		Listen:       listen,
		SessionTTL:   ttl,
		SecureCookie: raw.Session.Secure,
		DatabasePath: dbPath,
		BrandName:    brand,
		LogoPath:     logo,
		Mounts:       mounts,
	}, nil
}

func resolveDir(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if cleaned == string(filepath.Separator) {
		return "", errors.New("refusing to expose the filesystem root")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errors.New("path does not exist")
		}
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return resolved, nil
}

func sameOrNested(a, b string) bool {
	if a == b {
		return true
	}
	rel, err := filepath.Rel(a, b)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	rel, err = filepath.Rel(b, a)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	return false
}

func checkLogo(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("logo must be a regular file")
	}
	if info.Size() > maxLogoBytes {
		return errors.New("logo is larger than 2MiB")
	}
	buf := make([]byte, 12)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	switch ImageExtension(buf[:n]) {
	case ".png", ".jpg", ".webp":
		return nil
	default:
		return errors.New("logo must be png, jpeg, or webp")
	}
}

// ImageExtension reports the type of a PNG, JPEG, WEBP, GIF, or ICO from its
// magic bytes. Anything else, including SVG, returns an empty string.
func ImageExtension(data []byte) string {
	switch {
	case len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n":
		return ".png"
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return ".jpg"
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return ".webp"
	case len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a"):
		return ".gif"
	case len(data) >= 4 && (string(data[:4]) == "\x00\x00\x01\x00" || string(data[:4]) == "\x00\x00\x02\x00"):
		return ".ico"
	default:
		return ""
	}
}

// ValidMountID reports whether id can be used in a URL and a scope row.
func ValidMountID(id string) bool {
	return mountIDPattern.MatchString(id)
}
