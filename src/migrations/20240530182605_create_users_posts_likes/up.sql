CREATE TABLE users_posts_likes (
    user_id    UUID         NOT NULL,
    post_id    UUID         NOT NULL,
    PRIMARY KEY (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (post_id) REFERENCES posts(id)
);