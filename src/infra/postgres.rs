use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use std::env;
use tokio_postgres::NoTls;

/// # Postgres Configuration
///
/// This module provides a configuration for connecting to a PostgreSQL database using a connection pool.
///
/// # Purpose
///
/// The purpose of this method is to configure the database connection settings and create a connection pool that can be used throughout the application to interact with the PostgreSQL database.
///
/// # Usage
///
/// This method is typically called during the setup of the application to initialize the database connection pool. It reads the database configuration from environment variables.
///
/// # Returns
///
/// This method returns a `Pool` instance, which is used to manage database connections.
///
/// # Environment Variables
///
/// - `DB_HOST`: The hostname of the PostgreSQL server (e.g., `localhost`).
/// - `DB_PORT`: The port number on which the PostgreSQL server is listening (e.g., `5432`).
/// - `DB_NAME`: The name of the PostgreSQL database (e.g., `mydatabase`).
/// - `DB_USER`: The username for connecting to the PostgreSQL database (e.g., `myuser`).
/// - `DB_PASSWORD`: The password for the PostgreSQL user (e.g., `mypassword`).
/// - `DB_POOL_SIZE`: The size of the connection pool (e.g., `10`).
///
/// # Notes
///
/// - The `create_pool` method initializes the connection pool with the specified configuration.
/// - The `NoTls` argument specifies that no TLS encryption is used for the database connection. If you need TLS, you should configure it accordingly.
pub struct Postgres {}

impl Postgres {
    /// Initialize a connection pool to the PostgreSQL database.\
    ///
    /// # Returns
    ///
    /// A `Pool` instance that can be used to manage database connections.
    pub fn pool() -> Pool {
        let mut cfg = Config::new();
        cfg.host = Some(env::var("DB_HOST").unwrap());
        cfg.port = Some(env::var("DB_PORT").unwrap().parse().unwrap());
        cfg.dbname = Some(env::var("DB_NAME").unwrap());
        cfg.user = Some(env::var("DB_USER").unwrap());
        cfg.password = Some(env::var("DB_PASSWORD").unwrap());
        cfg.pool =
            PoolConfig::new(env::var("DB_POOL_SIZE").unwrap().parse::<usize>().unwrap()).into();
        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }
}
