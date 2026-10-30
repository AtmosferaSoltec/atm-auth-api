-- A client is the real customer: the person or business that owns one or more companies (tenants).
-- Systems use it to decide what companies may share (for example, the buyers of two stores of the same owner).
CREATE TABLE clients (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL CHECK (length(btrim(name)) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants ADD COLUMN client_id uuid REFERENCES clients (id) ON DELETE RESTRICT;

-- Every existing company starts as its own client, named after it. Joining the companies of one owner is
-- done afterwards from the console.
CREATE TEMPORARY TABLE tenant_clients ON COMMIT DROP AS
    SELECT t.id AS tenant_id, gen_random_uuid() AS client_id,
           coalesce(nullif(btrim(t.trade_name), ''), t.legal_name) AS name
      FROM tenants t;

INSERT INTO clients (id, name) SELECT client_id, name FROM tenant_clients;

UPDATE tenants t SET client_id = tc.client_id FROM tenant_clients tc WHERE tc.tenant_id = t.id;

ALTER TABLE tenants ALTER COLUMN client_id SET NOT NULL;

CREATE INDEX tenants_client_id_idx ON tenants (client_id);
