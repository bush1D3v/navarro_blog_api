CREATE TABLE tags (
    id                 UUID         PRIMARY KEY DEFAULT,
    name               VARCHAR(63)  NOT NULL    UNIQUE
);