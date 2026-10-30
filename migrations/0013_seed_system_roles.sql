-- The roles each system begins with, in code like the systems themselves (0012). Idempotent: a role that already
-- exists (with its description and the accesses that point at it) is left alone, and nothing is ever deleted.
INSERT INTO system_roles (system_id, name, description)
SELECT s.id, r.name, r.description
  FROM (VALUES
        ('pulso',      'admin',        'Manages the team, the gym settings and everything in the company.'),
        ('pulso',      'receptionist', 'Registers members, payments and entries in the branches assigned to them.'),
        ('lavendimia', 'admin',        'Manages the company, the catalog, the team and every sale.'),
        ('lavendimia', 'cashier',      'Registers sales and dispatches.')
       ) AS r (system_code, name, description)
  JOIN systems s ON s.code = r.system_code
ON CONFLICT (system_id, name) DO NOTHING;
