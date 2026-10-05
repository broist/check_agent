CREATE TABLE notification_preferences (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    warnings INTEGER NOT NULL,
    recovery INTEGER NOT NULL
);
