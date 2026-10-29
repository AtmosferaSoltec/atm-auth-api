-- One secret per system, so its backend can ask auth-api for a token and call any microservice.
-- Only the SHA-256 hash is stored: the secret is high-entropy random, so a fast hash is enough, and it is shown once.
ALTER TABLE systems
    ADD COLUMN secret_hash         text,
    ADD COLUMN secret_created_at   timestamptz,
    ADD COLUMN secret_last_used_at timestamptz;
