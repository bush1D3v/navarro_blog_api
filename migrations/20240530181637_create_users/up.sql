CREATE TABLE users (
    id         UUID         PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    name       VARCHAR(63)  NOT NULL,
    email      VARCHAR(127) NOT NULL    UNIQUE,
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ  DEFAULT     CURRENT_TIMESTAMP
);