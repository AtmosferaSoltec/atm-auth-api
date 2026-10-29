-- How long a user stays signed in to each system.
-- persistent: the refresh token lasts the global REFRESH_TOKEN_TTL, so the user is remembered.
-- temporary:  the refresh token lasts session_minutes of inactivity (it is renewed on use), so the user must sign in again after that.
ALTER TABLE systems
    ADD COLUMN session_mode    text NOT NULL DEFAULT 'persistent' CHECK (session_mode IN ('persistent', 'temporary')),
    ADD COLUMN session_minutes integer,
    ADD CONSTRAINT systems_session_policy CHECK (
        (session_mode = 'persistent' AND session_minutes IS NULL) OR
        -- NULL would pass a CHECK, so the minutes are required explicitly.
        (session_mode = 'temporary' AND session_minutes IS NOT NULL AND session_minutes BETWEEN 5 AND 1440)
    );
