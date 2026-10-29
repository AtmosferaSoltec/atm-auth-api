CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ruc        text NOT NULL UNIQUE CHECK (ruc ~ '^[0-9]{11}$'),
    legal_name text NOT NULL,
    trade_name text NOT NULL DEFAULT '',
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Which systems a tenant has contracted.
CREATE TABLE tenant_systems (
    tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    system_id  uuid NOT NULL REFERENCES systems (id) ON DELETE CASCADE,
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, system_id)
);

-- Which user can enter which system, in which tenant, with which role.
-- A user belongs to at most one tenant per system.
CREATE TABLE access (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL,
    system_id  uuid NOT NULL,
    tenant_id  uuid NOT NULL,
    role       text NOT NULL CHECK (length(role) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT access_user_system_key UNIQUE (user_id, system_id),
    CONSTRAINT access_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT access_tenant_system_fk FOREIGN KEY (tenant_id, system_id)
        REFERENCES tenant_systems (tenant_id, system_id) ON DELETE CASCADE
);

CREATE INDEX access_tenant_id_idx ON access (tenant_id);
