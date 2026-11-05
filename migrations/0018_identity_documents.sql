-- Foreign people have no Peruvian DNI: an account may be identified by a DNI, a foreign resident card (CE) or a
-- passport. Everything here only adds or relaxes, so the version that is still running keeps working.
--
-- The dni column keeps its name, because the running version reads it, but it now holds the number of any
-- document type. Numbers stay unique across types: the number alone is what a person types to sign in.

ALTER TABLE users ADD COLUMN document_type text;

UPDATE users SET document_type = 'dni' WHERE dni IS NOT NULL;

-- A missing type is a DNI: the running version still inserts accounts without it. Every branch uses COALESCE,
-- because a comparison with NULL makes the whole check NULL, and PostgreSQL accepts a NULL check.
ALTER TABLE users
    DROP CONSTRAINT users_dni_check,
    ADD CONSTRAINT users_document_type_check CHECK (document_type IN ('dni', 'ce', 'passport')),
    ADD CONSTRAINT users_document_type_needs_number CHECK (document_type IS NULL OR dni IS NOT NULL),
    ADD CONSTRAINT users_document_form CHECK (
        dni IS NULL
        OR (COALESCE(document_type, 'dni') = 'dni' AND dni ~ '^[0-9]{8}$')
        OR (COALESCE(document_type, 'dni') = 'ce' AND dni ~ '^[0-9]{9,12}$')
        OR (COALESCE(document_type, 'dni') = 'passport' AND dni ~ '^[A-Z0-9]{6,12}$')
    );
