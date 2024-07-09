CREATE TABLE users (
    id         UUID         PRIMARY KEY NOT NULL,
    name       VARCHAR(63)  NOT NULL,
    email      VARCHAR(127) NOT NULL    UNIQUE,
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL
);
