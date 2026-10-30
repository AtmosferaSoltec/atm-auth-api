-- Company profile data that every system reads from here instead of keeping its own copy.
-- All optional: an empty string means "not set", like trade_name. The logo is the id of a
-- company asset in atm-storage-api (never a URL, which is signed and expires).
ALTER TABLE tenants
    ADD COLUMN address       text NOT NULL DEFAULT '',
    ADD COLUMN department    text NOT NULL DEFAULT '',
    ADD COLUMN province      text NOT NULL DEFAULT '',
    ADD COLUMN district      text NOT NULL DEFAULT '',
    ADD COLUMN ubigeo        text NOT NULL DEFAULT '' CHECK (ubigeo = '' OR ubigeo ~ '^[0-9]{6}$'),
    ADD COLUMN phone         text NOT NULL DEFAULT '',
    ADD COLUMN email         text NOT NULL DEFAULT '',
    ADD COLUMN logo_file_id  uuid;
