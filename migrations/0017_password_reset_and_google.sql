-- Password recovery by emailed code, and sign-in with Google. Only adds tables.

CREATE TABLE password_reset_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- HMAC-SHA256 of the code with a key derived from the server secret: a leaked table cannot be brute-forced offline.
    code_hash  bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    -- Failed attempts; the code stops working at the fifth.
    attempts   smallint NOT NULL DEFAULT 0,
    -- Used, or replaced by a newer one.
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_codes_active_idx ON password_reset_codes (user_id) WHERE used_at IS NULL;
CREATE INDEX password_reset_codes_user_created_idx ON password_reset_codes (user_id, created_at);

-- One identity per provider per person: the provider's subject is what identifies them, never their email.
CREATE TABLE external_identities (
    provider   text NOT NULL CHECK (provider IN ('google')),
    subject    text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject),
    UNIQUE (user_id, provider)
);

-- Single-use nonce that binds a Google credential to the browser or app that asked for it.
CREATE TABLE google_login_challenges (
    nonce_hash bytea PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX google_login_challenges_expiry_idx ON google_login_challenges (expires_at);
