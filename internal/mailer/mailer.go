// Package mailer sends transactional emails through atm-messaging-api (POST /v1/email). The service token it
// presents is signed here, so no secret is shared: messaging verifies it with the public key like any other caller.
package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

// ErrUnavailable means no messaging service is configured.
var ErrUnavailable = errors.New("mailer: messaging service not configured")

// TokenSigner signs the service token. platform.TokenSigner satisfies it.
type TokenSigner interface {
	Sign(c platform.Claims) (string, error)
}

type Client struct {
	baseURL string
	signer  TokenSigner
	http    *http.Client
	now     func() time.Time
}

// New returns a client for the messaging service at baseURL. An empty baseURL gives a client that always
// answers ErrUnavailable, so the rest of the service keeps working without email.
func New(baseURL string, signer TokenSigner, now func() time.Time) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"), signer: signer, now: now,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

type emailRequest struct {
	To             string         `json:"to"`
	Template       string         `json:"template"`
	Data           map[string]any `json:"data"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
}

// SendResetCode emails a password recovery code on behalf of system.
func (c *Client) SendResetCode(ctx context.Context, system, to, name, code string, validFor time.Duration) error {
	return c.send(ctx, system, emailRequest{
		To: to, Template: "password_reset_code",
		Data: map[string]any{"name": name, "code": code, "expires_minutes": int(validFor.Minutes())},
	})
}

// SendPasswordChanged tells the owner of an account that its password was changed.
func (c *Client) SendPasswordChanged(ctx context.Context, system, to, name string) error {
	return c.send(ctx, system, emailRequest{
		To: to, Template: "password_changed", Data: map[string]any{"name": name},
	})
}

func (c *Client) send(ctx context.Context, system string, body emailRequest) error {
	if c.baseURL == "" {
		return ErrUnavailable
	}
	now := c.now()
	token, err := c.signer.Sign(platform.Claims{
		Subject: "system:" + system, Role: "service", System: system,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		return fmt.Errorf("sign service token: %w", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode email request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/email", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send email request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		// The body never contains the code; it is safe to keep a short piece of it for the log.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("messaging answered %d: %s", resp.StatusCode, snippet)
	}
	return nil
}
