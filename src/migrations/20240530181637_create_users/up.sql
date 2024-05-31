CREATE TABLE users (
    id         UUID         PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    name       VARCHAR(63)  NOT NULL,
    email      VARCHAR(127) NOT NULL,
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMP    DEFAULT     CURRENT_TIMESTAMP
);