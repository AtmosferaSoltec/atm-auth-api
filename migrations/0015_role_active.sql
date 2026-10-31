-- A role that leaves the catalog is not deleted (accesses may still point at it): the catalog sync marks it inactive,
-- and an inactive role cannot be given to anyone. Existing roles stay active until the next sync decides otherwise.
ALTER TABLE system_roles ADD COLUMN active boolean NOT NULL DEFAULT true;
