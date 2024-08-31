use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use std::env;
use tokio_postgres::NoTls;

/// Models for Postgres
///
/// It contains the Postgres Pool Connection models.
///
/// # Functions
///
/// - `postgres_success()` - It creates a Success Postgres Pool Connection.
/// - `postgres_error()` - It creates a Error Postgres Pool Connection.
pub struct PostgresModels {}

impl PostgresModels {
    /// Postgres Success model
    ///
    /// It creates a Success Postgres Pool Connection.
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to guarantee that Postgres is available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::postgres::PostgresModels;
    ///
    /// let pool = PostgresModels::postgres_success();
    /// ```
    pub fn postgres_success() -> Pool {
        let mut cfg: Config = Config::new();
        cfg.host = Some(env::var("DB_HOST").unwrap());
        cfg.port = Some(env::var("DB_PORT").unwrap().parse().unwrap());
        cfg.dbname = Some(env::var("DB_NAME").unwrap());
        cfg.user = Some(env::var("DB_USER").unwrap());
        cfg.password = Some(env::var("DB_PASSWORD").unwrap());
        cfg.pool =
            PoolConfig::new(env::var("DB_POOL_SIZE").unwrap().parse::<usize>().unwrap()).into();

        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }

    /// Postgres Error model
    ///
    /// It creates a Error Postgres Pool Connection.
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to throw a postgres connection error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::postgres::PostgresModels;
    ///
    /// let pool = PostgresModels::postgres_error();
    /// ```
    pub fn postgres_error() -> Pool {
        let mut cfg: Config = Config::new();
        cfg.host = Some(env::var("DB_HOST").unwrap());
        cfg.port = Some(env::var("DB_PORT").unwrap().parse().unwrap());
        cfg.dbname = Some(env::var("DB_NAME").unwrap());
        cfg.user = Some(env::var("DB_USER").unwrap());
        cfg.password = Some(String::from("5555"));
        cfg.pool =
            PoolConfig::new(env::var("DB_POOL_SIZE").unwrap().parse::<usize>().unwrap()).into();

        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }
}
