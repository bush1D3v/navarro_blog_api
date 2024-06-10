CREATE TABLE posts_categories (
    post_id        UUID         NOT NULL,
    category_id    UUID         NOT NULL,
    PRIMARY KEY (post_id, category_id),
    FOREIGN KEY (post_id)                   REFERENCES posts(id),
    FOREIGN KEY (category_id)               REFERENCES categories(id)
);