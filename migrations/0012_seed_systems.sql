-- The catalog of systems lives in code: a new system is added by a migration like this one, not from the console.
-- Idempotent on purpose: a system that already exists (with its secret, session policy and roles) is left alone.
-- Secrets are never seeded; they are generated per environment from the console.
INSERT INTO systems (code, name) VALUES
    ('lavendimia', 'La Vendimia'),
    ('pulso', 'Pulso')
ON CONFLICT (code) DO NOTHING;
