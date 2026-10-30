-- A person can work for several companies inside the same system (for example the owner of two
-- businesses). The access is now unique per user, system AND tenant.
ALTER TABLE access DROP CONSTRAINT access_user_system_key;
ALTER TABLE access ADD CONSTRAINT access_user_system_tenant_key UNIQUE (user_id, system_id, tenant_id);

-- Which access the person used last in a system: login enters it by default.
ALTER TABLE access ADD COLUMN last_used_at timestamptz;

-- A session remembers its company, so a refresh keeps it instead of guessing. Sessions that already
-- exist were created when a user had one company per system, so that one is the one to keep.
ALTER TABLE refresh_tokens ADD COLUMN tenant_id uuid REFERENCES tenants (id) ON DELETE CASCADE;
UPDATE refresh_tokens rt SET tenant_id = a.tenant_id
  FROM access a
 WHERE rt.role = 'user' AND a.user_id = rt.user_id AND a.system_id = rt.system_id;
