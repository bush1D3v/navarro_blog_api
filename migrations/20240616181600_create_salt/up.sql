CREATE TABLE salt (
    salt           UUID         NOT NULL,
    user_id        UUID         NOT NULL,
    PRIMARY KEY (salt),
    FOREIGN KEY (user_id)                   REFERENCES users(id)
);
