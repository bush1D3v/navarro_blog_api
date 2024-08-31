/// Enum that contains the names of the tables in the database.
///
/// It is used in the `FunctionalTester` struct to determine the table to use in the tests.
///
/// # Examples
///
/// ```rust
/// use tests::mocks::enums::db_table::TablesEnum;
///
/// let table = TablesEnum::Users;
/// ```
pub enum TablesEnum {
    Users,
    Salt,
    _Posts,
    _Categories,
    _Tags,
    _Comments,
    _PostsTags,
    _PostsCategories,
    _UsersPostsLikes,
    _UsersCommentsLikes,
}
