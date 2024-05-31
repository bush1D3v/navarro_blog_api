CREATE TABLE posts_tags (
    post_id       UUID         NOT NULL,
    tag_id        UUID         NOT NULL,
    PRIMARY KEY (post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);