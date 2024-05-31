pub struct _Post<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub subtitle: &'a str,
    pub body: &'a str,
    pub created_at: &'a str,
    pub likes: i32,
}
