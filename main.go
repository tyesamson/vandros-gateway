package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tyesamson/vandros-gateway/auth"
	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/handlers"
	"github.com/tyesamson/vandros-gateway/storage"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("vandros", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "config.yaml", "path to configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret := os.Getenv("VANDROS_SESSION_SECRET")
	if len(secret) < 32 {
		return errors.New("VANDROS_SESSION_SECRET must be at least 32 characters")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logo, logoType, err := loadLogo(cfg.LogoPath)
	if err != nil {
		return err
	}
	users, err := auth.Open(cfg.DatabasePath, secret)
	if err != nil {
		return err
	}
	defer users.Close()
	if err := users.EnsureAdmin(context.Background(), os.Getenv("VANDROS_ADMIN_USER"), os.Getenv("VANDROS_ADMIN_PASSWORD")); err != nil {
		return err
	}
	_ = os.Unsetenv("VANDROS_ADMIN_PASSWORD")
	if err := users.EnsureBranding(context.Background(), cfg.BrandName); err != nil {
		return err
	}
	portal, err := storage.Open(cfg.Mounts)
	if err != nil {
		return err
	}
	defer portal.Close()

	app := &handlers.Server{
		Brand:        cfg.BrandName,
		Logo:         logo,
		LogoType:     logoType,
		SecureCookie: cfg.SecureCookie,
		SessionTTL:   cfg.SessionTTL,
		DataDir:      filepath.Dir(cfg.DatabasePath),
		Portal:       portal,
		Users:        users,
		Log:          log,
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
	log.Info("listening", "addr", cfg.Listen, "mounts", len(cfg.Mounts))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shut); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

func loadLogo(path string) ([]byte, string, error) {
	if path == "" {
		return nil, "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("branding.logo: %w", err)
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if err != nil {
		return nil, "", fmt.Errorf("branding.logo: %w", err)
	}
	if len(body) > 2<<20 {
		return nil, "", errors.New("branding.logo is larger than 2MiB")
	}
	switch config.ImageExtension(body) {
	case ".png":
		return body, "image/png", nil
	case ".jpg":
		return body, "image/jpeg", nil
	case ".webp":
		return body, "image/webp", nil
	default:
		return nil, "", errors.New("branding.logo must be png, jpeg, or webp")
	}
}
