CREATE TABLE comments (
    id                 UUID         PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    post_id            UUID         NOT NULL,
    user_id            UUID         NOT NULL,
    parent_comment_id  UUID         NULL,
    body               TEXT         NOT NULL,
    likes              INT          DEFAULT     0,
    created_at         TIMESTAMP    DEFAULT     CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id)   REFERENCES posts (id),
    FOREIGN KEY (user_id)   REFERENCES users (id),
    FOREIGN KEY (parent_comment_id) REFERENCES comments (id)
);