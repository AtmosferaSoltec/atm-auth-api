-- A temporary session no longer carries a number of minutes. It lasts until the person signs out or closes the
-- tab (the client does not keep it); the server only keeps a fixed ceiling for tokens that get left behind
-- (TEMPORARY_REFRESH_TTL). A persistent session lasts REFRESH_TOKEN_TTL without use.
ALTER TABLE systems
    DROP CONSTRAINT systems_session_policy,
    DROP COLUMN session_minutes;
