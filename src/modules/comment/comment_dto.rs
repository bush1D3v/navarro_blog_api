pub struct _Comment<'a> {
    pub id: &'a str,
    pub post_id: &'a str,
    pub user_id: &'a str,
    pub parent_comment_id: &'a str,
    pub body: &'a str,
    pub likes: i32,
    pub created_at: &'a str,
}
