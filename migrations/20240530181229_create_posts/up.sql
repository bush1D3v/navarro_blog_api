CREATE TABLE posts (
    id         UUID         PRIMARY KEY NOT NULL,
    title      VARCHAR(127) NOT NULL,
    subtitle   VARCHAR(255) NOT NULL,
    body       TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    likes      INT          DEFAULT     0
);
