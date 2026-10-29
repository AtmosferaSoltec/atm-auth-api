package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/config"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/server"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/system"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/tenant"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
	"github.com/AtmosferaSoltec/atm-auth-api/migrations"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := platform.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := platform.Migrate(ctx, pool, migrations.Files); err != nil {
		return err
	}

	signer, err := platform.NewTokenSigner(cfg.JWTPrivateKey, cfg.JWTIssuer, time.Now)
	if err != nil {
		return err
	}
	jwks, err := signer.JWKS()
	if err != nil {
		return err
	}

	hasher := platform.NewPasswordHasher(platform.Argon2Params(cfg.Argon2))
	dummyHash, err := hasher.Hash("dummy-password-for-timing")
	if err != nil {
		return err
	}
	sessionRepo := session.NewPostgresRepository(pool)
	userRepo := user.NewPostgresRepository(pool)
	accessSvc := access.NewService(access.NewPostgresRepository(pool))
	sessionSvc := session.NewService(session.Deps{
		Tokens:   sessionRepo,
		Attempts: sessionRepo,
		Users:    userRepo,
		Access:   accessSvc,
		Hasher:   hasher,
		Signer:   signer,
	}, session.Config{
		Admin:     session.AdminCredentials{DNI: cfg.AdminDNI, PasswordHash: cfg.AdminPasswordHash},
		DummyHash: dummyHash,
		Limits: session.Limits{
			MaxPerSubject: cfg.LoginMaxPerSubject, MaxPerIP: cfg.LoginMaxPerIP, Window: cfg.LoginWindow,
		},
		AccessTTL:  cfg.AccessTTL,
		RefreshTTL: cfg.RefreshTTL,
	}, time.Now)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: server.New(log, server.Deps{
			DB:       pool,
			Verifier: signer,
			JWKS:     jwks,
			Session:  session.NewHandler(sessionSvc, log, cfg.ClientIPHeader),
			Systems:  system.NewHandler(system.NewService(system.NewPostgresRepository(pool)), log),
			Tenants:  tenant.NewHandler(tenant.NewService(tenant.NewPostgresRepository(pool)), log),
			Users:    user.NewHandler(user.NewService(userRepo, hasher, sessionSvc), log),
			Access:   access.NewHandler(accessSvc, log),
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", cfg.HTTPAddr, "env", cfg.Env)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
