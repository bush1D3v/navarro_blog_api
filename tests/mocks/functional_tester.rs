use super::{
    enums::db_table::TablesEnum,
    models::{postgres::PostgresModels, redis::RedisModels, user::UserModels},
    structs::user::MockUserDTO,
};
use sql_builder::{quote, SqlBuilder};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SaltDTO {
    pub salt: String,
    pub user_id: String,
}

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

    pub async fn delete_from_database(db_table: TablesEnum, conditions: Option<Vec<(&str, &str)>>) {
        let client = PostgresModels::postgres_success().get().await.unwrap();
        let mut sql = SqlBuilder::delete_from(FunctionalTester::construct_table(db_table).db_table);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                sql.or_where_eq(key, &quote(&value));
            }
        }

        let stmt = sql.sql().unwrap();

        client.prepare(&stmt).await.unwrap();
        client.execute(&stmt, &[]).await.unwrap();

        let mut redis_conn = RedisModels::pool_success().await.get().await.unwrap();
        let _: () = deadpool_redis::redis::cmd("FLUSHDB")
            .query_async(&mut redis_conn)
            .await
            .unwrap();
    }

    pub async fn can_see_in_database(
        db_table: TablesEnum,
        field: &str,
        conditions: Option<Vec<(&str, &str)>>,
    ) -> bool {
        let mut conn = PostgresModels::postgres_success().get().await.unwrap();
        let transaction = conn.transaction().await.unwrap();

        let mut sql_builder =
            SqlBuilder::select_from(FunctionalTester::construct_table(db_table).db_table);
        sql_builder.field(field);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                sql_builder.or_where_eq(key, &quote(&value));
            }
        }

        let sql = sql_builder.sql().unwrap();
        let rows = transaction.query(&sql, &[]).await.unwrap();
        transaction.commit().await.unwrap();

        !rows.is_empty()
    }

    pub async fn cant_see_in_database(
        db_table: TablesEnum,
        field: &str,
        conditions: Option<Vec<(&str, &str)>>,
    ) -> bool {
        let mut conn = PostgresModels::postgres_success().get().await.unwrap();
        let transaction = conn.transaction().await.unwrap();

        let mut sql_builder =
            SqlBuilder::select_from(FunctionalTester::construct_table(db_table).db_table);
        sql_builder.field(field);

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                sql_builder.or_where_eq(key, &quote(&value));
            }
        }

        let sql = sql_builder.sql().unwrap();
        let rows = transaction.query(&sql, &[]).await.unwrap();
        transaction.commit().await.unwrap();

        rows.is_empty()
    }

    pub async fn insert_in_db_salt(user_id: String, salt: String) -> String {
        let client = PostgresModels::postgres_success().get().await.unwrap();

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

    pub async fn get_salt_from_db(conditions: Option<Vec<(&str, &str)>>) -> SaltDTO {
        let mut conn = PostgresModels::postgres_success().get().await.unwrap();
        let transaction = conn.transaction().await.unwrap();

        let mut sql_builder = SqlBuilder::select_from("salt");

        if let Some(conditions) = conditions {
            for (key, value) in conditions {
                sql_builder.or_where_eq(key, &quote(&value));
            }
        }

        let sql = sql_builder.sql().unwrap();
        let rows = transaction.query(&sql, &[]).await.unwrap();
        transaction.commit().await.unwrap();

        let salt: uuid::Uuid = rows[0].get("salt");
        let user_id: uuid::Uuid = rows[0].get("user_id");

        SaltDTO {
            salt: salt.to_string(),
            user_id: user_id.to_string(),
        }
    }

    pub async fn insert_in_db_users(user_body: MockUserDTO) -> MockUserDTO {
        let mut pg_user = MockUserDTO {
            id: user_body.id.clone(),
            name: user_body.name.clone(),
            email: user_body.email.clone(),
            password: user_body.password.clone(),
            created_at: user_body.created_at.clone(),
            updated_at: user_body.updated_at.clone(),
        };

        if user_body.id == *"" {
            pg_user.id = UserModels::complete_user_model_hashed().id;
        }
        if user_body.name == *"" {
            pg_user.name = UserModels::complete_user_model_hashed().name;
        }
        if user_body.email == *"" {
            pg_user.email = UserModels::complete_user_model_hashed().email;
        }
        if user_body.password == *"" {
            pg_user.password = UserModels::complete_user_model_hashed().password;
        }
        if user_body.created_at == *"" {
            pg_user.created_at = UserModels::complete_user_model_hashed().created_at;
        }

        let client = PostgresModels::postgres_success().get().await.unwrap();

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

    pub async fn get_user_from_db() -> String {
        let client = PostgresModels::postgres_success().get().await.unwrap();
        let stmt = client.prepare("SELECT salt FROM salt").await.unwrap();
        let rows = client.query(&stmt, &[]).await.unwrap();
        rows[0].get("salt")
    }
}
