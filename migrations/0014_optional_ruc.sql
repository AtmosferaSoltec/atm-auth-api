-- A company does not always have a RUC: a gym run by one person can be registered with just its name. The column
-- becomes optional; its UNIQUE constraint keeps working because PostgreSQL treats NULLs as distinct, so a RUC is
-- unique only when present. The format check passes on NULL. Never store an empty string: the code writes NULL.
ALTER TABLE tenants ALTER COLUMN ruc DROP NOT NULL;

-- Whether a system can only be enabled for companies that have a RUC (invoicing systems). Pulso does not need one.
ALTER TABLE systems ADD COLUMN requires_ruc boolean NOT NULL DEFAULT true;
UPDATE systems SET requires_ruc = false WHERE code = 'pulso';
