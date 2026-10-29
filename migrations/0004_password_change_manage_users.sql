ALTER TABLE users  ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
ALTER TABLE access ADD COLUMN manage_users         boolean NOT NULL DEFAULT false;
