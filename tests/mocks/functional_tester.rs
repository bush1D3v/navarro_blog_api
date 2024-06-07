use super::{enums::db_table::TablesEnum, models::user::user};
use deadpool_postgres::Pool;
use navarro_blog_api::dtos::user::CreateUserDTO;
use std::collections::HashMap;

pub struct FunctionalTester {
    db_table: String,
}

impl std::fmt::Display for FunctionalTester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.db_table)
    }
}

impl FunctionalTester {
    pub fn construct_table(db_table: &TablesEnum) -> Self {
        let table: &str = match db_table {
            TablesEnum::Users => "users",
            TablesEnum::_Posts => "posts",
            TablesEnum::_Categories => "categories",
            TablesEnum::_Tags => "tags",
            TablesEnum::_Comments => "comments",
            TablesEnum::_PostsTags => "posts_tags",
            TablesEnum::_PostsCategories => "posts_categories",
            TablesEnum::_UsersPostsLikes => "users_posts_likes",
            TablesEnum::_UsersCommentsLikes => "users_comments_likes",
        };

        Self {
            db_table: table.to_string(),
        }
    }

    pub async fn delete_from_database(pool: Pool, db_table: &TablesEnum) {
        let client = pool.get().await.unwrap();

        client
            .execute(
                &format!(
                    "DELETE FROM {};",
                    FunctionalTester::construct_table(db_table)
                ),
                &[],
            )
            .await
            .unwrap();
    }

    pub async fn can_see_in_database(
        pool: Pool,
        db_table: &TablesEnum,
        conditions: Option<HashMap<String, String>>,
    ) -> bool {
        let client = pool.get().await.unwrap();

        let conditions_query = if let Some(conditions) = conditions {
            let conditions_str: Vec<String> = conditions
                .into_iter()
                .map(|(key, value)| format!("{} = {}", key, value))
                .collect();

            conditions_str.join(" AND ")
        } else {
            String::new()
        };

        let stmt = if conditions_query.is_empty() {
            client
                .prepare(&format!(
                    "SELECT * FROM {}",
                    FunctionalTester::construct_table(db_table).db_table,
                ))
                .await
                .unwrap()
        } else {
            client
                .prepare(&format!(
                    "SELECT * FROM {} WHERE {}",
                    FunctionalTester::construct_table(db_table).db_table,
                    conditions_query
                ))
                .await
                .unwrap()
        };

        let rows = client.query(&stmt, &[]).await.unwrap();

        if rows.len() > 0 {
            true
        } else {
            false
        }
    }

    pub async fn cant_see_in_database(
        pool: Pool,
        db_table: &TablesEnum,
        conditions: Option<HashMap<String, String>>,
    ) -> bool {
        let client = pool.get().await.unwrap();

        let conditions_query = if let Some(conditions) = conditions {
            let conditions_str: Vec<String> = conditions
                .into_iter()
                .map(|(key, value)| format!("{} = {}", key, value))
                .collect();

            conditions_str.join(" AND ")
        } else {
            String::new()
        };

        let stmt = if conditions_query.is_empty() {
            client
                .prepare(&format!(
                    "SELECT * FROM {}",
                    FunctionalTester::construct_table(db_table).db_table,
                ))
                .await
                .unwrap()
        } else {
            client
                .prepare(&format!(
                    "SELECT * FROM {} WHERE {}",
                    FunctionalTester::construct_table(db_table).db_table,
                    conditions_query
                ))
                .await
                .unwrap()
        };

        let rows = client.query(&stmt, &[]).await.unwrap();

        if rows.len() > 0 {
            false
        } else {
            true
        }
    }

    pub async fn insert_in_db_users(pool: Pool, user_body: CreateUserDTO) -> CreateUserDTO {
        let mut pg_user: CreateUserDTO = CreateUserDTO {
            name: user_body.name.clone(),
            email: user_body.email.clone(),
            password: user_body.password.clone(),
        };

        if user_body.name == String::from("") {
            pg_user.name = user().name;
        }
        if user_body.email == String::from("") {
            pg_user.email = user().email;
        }
        if user_body.password == String::from("") {
            pg_user.password = user().password;
        }

        let client = pool.get().await.unwrap();

        let stmt = client
            .prepare(
                "INSERT INTO users
                (name, email, password)
                values
                ($1, $2, $3)",
            )
            .await
            .unwrap();

        client
            .query(&stmt, &[&pg_user.name, &pg_user.email, &pg_user.password])
            .await
            .unwrap();

        pg_user
    }
}
