use super::{enums::db_table::TablesEnum, models::user::complete_user_model};
use deadpool_postgres::Pool;
use navarro_blog_api::modules::user::user_dtos::UserDTO;
use sql_builder::prelude::*;

pub struct FunctionalTester {
    db_table: String,
}

impl std::fmt::Display for FunctionalTester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.db_table)
    }
}

impl FunctionalTester {
    pub fn construct_table(db_table: TablesEnum) -> Self {
        let table = match db_table {
            TablesEnum::Users => "users",
            TablesEnum::Salt => "salt",
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

    pub async fn delete_from_database(
        pool: Pool,
        db_table: TablesEnum,
        conditions: Option<Vec<(&str, &str)>>,
    ) {
        let client = pool.get().await.unwrap();
        let mut sql = SqlBuilder::delete_from(FunctionalTester::construct_table(db_table).db_table);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                if key.contains("id") {
                    sql.field(&key);
                    sql.values(&[&quote(uuid::Uuid::parse_str(value).unwrap())]);
                } else {
                    sql.field(&key);
                    sql.values(&[&quote(value)]);
                }
            }
        }

        let stmt = sql.sql().unwrap();

        client.prepare(&stmt).await.unwrap();
        client.execute(&stmt, &[]).await.unwrap();
    }

    pub async fn can_see_in_database(
        pool: Pool,
        db_table: TablesEnum,
        conditions: Option<Vec<(&str, &str)>>,
    ) -> bool {
        let client = pool.get().await.unwrap();

        let mut sql = SqlBuilder::select_from(FunctionalTester::construct_table(db_table).db_table);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                if key.contains("id") {
                    sql.and_where(format!(
                        "\"{}\" = {}",
                        key,
                        uuid::Uuid::parse_str(value).unwrap()
                    ));
                } else {
                    sql.and_where(format!("\"{}\" = '{}'", key, value));
                }
            }
        }

        let stmt = sql.sql().unwrap();

        let stmt = client.prepare(&stmt).await.unwrap();
        let rows = client.query(&stmt, &[]).await.unwrap();

        !rows.is_empty()
    }

    pub async fn cant_see_in_database(
        pool: Pool,
        db_table: TablesEnum,
        conditions: Option<Vec<(&str, &str)>>,
    ) -> bool {
        let client = pool.get().await.unwrap();

        let mut sql = SqlBuilder::select_from(FunctionalTester::construct_table(db_table).db_table);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                if key.contains("id") {
                    sql.and_where(format!(
                        "\"{}\" = {}",
                        key,
                        uuid::Uuid::parse_str(value).unwrap()
                    ));
                } else {
                    sql.and_where(format!("\"{}\" = '{}'", key, value));
                }
            }
        }

        let stmt = sql.sql().unwrap();

        let stmt = client.prepare(&stmt).await.unwrap();
        let rows = client.query(&stmt, &[]).await.unwrap();

        rows.is_empty()
    }

    pub async fn insert_in_db_salt(pool: Pool, user_id: String, salt: String) -> String {
        let client = pool.get().await.unwrap();

        let user_id2 = uuid::Uuid::parse_str(&user_id).unwrap();
        let salt2 = uuid::Uuid::parse_str(&salt).unwrap();

        let stmt = client
            .prepare(
                "INSERT INTO salt
                (user_id, salt)
                values
                ($1, $2)",
            )
            .await
            .unwrap();

        client.query(&stmt, &[&user_id2, &salt2]).await.unwrap();

        salt
    }

    pub async fn get_salt_from_db(pool: Pool) -> String {
        let client = pool.get().await.unwrap();
        let stmt = client.prepare("SELECT salt FROM salt").await.unwrap();
        let rows = client.query(&stmt, &[]).await.unwrap();
        rows[0].get("salt")
    }

    pub async fn insert_in_db_users(pool: Pool, user_body: UserDTO) -> UserDTO {
        let mut pg_user = UserDTO {
            id: user_body.id.clone(),
            name: user_body.name.clone(),
            email: user_body.email.clone(),
            password: user_body.password.clone(),
            created_at: user_body.created_at.clone(),
        };

        if user_body.id == *"" {
            pg_user.id = complete_user_model().id;
        }
        if user_body.name == *"" {
            pg_user.name = complete_user_model().name;
        }
        if user_body.email == *"" {
            pg_user.email = complete_user_model().email;
        }
        if user_body.password == *"" {
            pg_user.password = complete_user_model().password;
        }
        if user_body.created_at == *"" {
            pg_user.created_at = complete_user_model().created_at;
        }

        let client = pool.get().await.unwrap();

        let stmt = client
            .prepare(
                "INSERT INTO users
                (id, name, email, password, created_at)
                values
                ($1, $2, $3, $4, $5)",
            )
            .await
            .unwrap();

        let uuid_id = uuid::Uuid::parse_str(&pg_user.id).unwrap();

        client
            .query(
                &stmt,
                &[
                    &uuid_id,
                    &pg_user.name,
                    &pg_user.email,
                    &pg_user.password,
                    &chrono::Utc::now(),
                ],
            )
            .await
            .unwrap();

        pg_user
    }
}
