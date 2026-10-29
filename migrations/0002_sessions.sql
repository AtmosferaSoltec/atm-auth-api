CREATE TABLE refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id  uuid NOT NULL DEFAULT gen_random_uuid(),
    token_hash text NOT NULL UNIQUE,
    role       text NOT NULL CHECK (role IN ('superadmin', 'user')),
    user_id    uuid REFERENCES users (id) ON DELETE CASCADE,
    system_id  uuid REFERENCES systems (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (role = 'superadmin' AND user_id IS NULL AND system_id IS NULL) OR
        (role = 'user' AND user_id IS NOT NULL AND system_id IS NOT NULL)
    )
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);

CREATE TABLE login_attempts (
    key          text NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_key_idx ON login_attempts (key, attempted_at);
