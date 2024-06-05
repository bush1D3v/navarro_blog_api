CREATE TABLE categories (
    id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name               VARCHAR(63)  NOT NULL    UNIQUE
);