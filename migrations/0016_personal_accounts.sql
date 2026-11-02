-- Personal accounts: systems whose people sign in with an email and belong to no company (Orbita).
-- Everything here only adds or relaxes, so the version that is still running keeps working.

-- A person is identified by a DNI, an email, or both.
ALTER TABLE users
    ALTER COLUMN dni DROP NOT NULL,
    -- Accounts created with Google have no password until the person sets one.
    ALTER COLUMN password_hash DROP NOT NULL,
    ADD COLUMN email text,
    ADD COLUMN email_verified_at timestamptz,
    ADD CONSTRAINT users_email_form CHECK (email IS NULL OR (email = lower(email) AND email = btrim(email) AND length(email) BETWEEN 3 AND 254)),
    ADD CONSTRAINT users_identifier_present CHECK (dni IS NOT NULL OR email IS NOT NULL);

CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;

-- personal: people of this system have no company, so their access has no tenant.
-- self_signup: anyone may create an account in this system. self_signup_role is the role they get.
ALTER TABLE systems
    ADD COLUMN personal         boolean NOT NULL DEFAULT false,
    ADD COLUMN self_signup      boolean NOT NULL DEFAULT false,
    ADD COLUMN self_signup_role text,
    ADD CONSTRAINT systems_self_signup_role CHECK (NOT self_signup OR self_signup_role IS NOT NULL);

-- An access without tenant is only valid for a personal system (the service enforces it).
-- The composite foreign key to tenant_systems is skipped by PostgreSQL when tenant_id is NULL.
ALTER TABLE access ALTER COLUMN tenant_id DROP NOT NULL;
CREATE UNIQUE INDEX access_personal_user_system_key ON access (user_id, system_id) WHERE tenant_id IS NULL;
