-- The roles each system defines. An access points at one of them, so a role cannot be mistyped
-- and a role in use cannot be deleted. The role is still free text inside the token (app_role).
CREATE TABLE system_roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    system_id   uuid NOT NULL REFERENCES systems (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 200),
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT system_roles_system_name_key UNIQUE (system_id, name)
);

-- The roles already handed out become part of the catalog, so nothing that exists breaks.
INSERT INTO system_roles (system_id, name) SELECT DISTINCT system_id, role FROM access;

-- NO ACTION (not RESTRICT): deleting a whole system removes its accesses and its roles in the same
-- statement, and the check has to wait until both are gone. Deleting one role that is in use still fails.
ALTER TABLE access
    ADD CONSTRAINT access_role_fk FOREIGN KEY (system_id, role) REFERENCES system_roles (system_id, name);
