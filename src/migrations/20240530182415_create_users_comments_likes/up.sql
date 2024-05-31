CREATE TABLE users_comments_likes (
    user_id       UUID         NOT NULL,
    comment_id    UUID         NOT NULL,
    PRIMARY KEY (user_id, comment_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (comment_id) REFERENCES comments(id)
);