CREATE TABLE tags (
    id                 UUID         PRIMARY KEY,
    name               VARCHAR(63)  NOT NULL    UNIQUE,
    created_at         TIMESTAMPTZ  NOT NULL
);
