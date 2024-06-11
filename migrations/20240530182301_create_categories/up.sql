CREATE TABLE categories (
    id                 UUID         PRIMARY KEY,
    name               VARCHAR(63)  NOT NULL    UNIQUE
);