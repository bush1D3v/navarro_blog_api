CREATE TABLE tags (
    id                 UUID         PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    name               VARCHAR(63)  NOT NULL
);