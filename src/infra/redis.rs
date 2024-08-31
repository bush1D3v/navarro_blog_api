use deadpool_redis::{
    redis::{cmd, RedisResult},
    Config, ConnectionAddr, ConnectionInfo, Pool, PoolConfig, RedisConnectionInfo, Runtime,
    Timeouts,
};
use std::{env, time::Duration};

/// # Redis Configuration and Operations
///
/// This module provides a configuration for connecting to a Redis database using a connection pool and defines methods for common Redis operations.
///
/// The `Redis` struct contains methods to create and configure a connection pool to the Redis database, as well as methods to perform `SET`, `GET`, and `DELETE` operations.
///
/// # Environment Variables
///
/// - `REDIS_HOST`: The hostname of the Redis server (e.g., `localhost`).
/// - `REDIS_PORT`: The port number on which the Redis server is listening (e.g., `6379`).
/// - `REDIS_NUMBER`: The Redis database number (e.g., `0`).
/// - `REDIS_USER`: The username for connecting to the Redis database (if applicable).
/// - `REDIS_PASSWORD`: The password for the Redis user (if applicable).
/// - `REDIS_POOL_SIZE`: The size of the connection pool (e.g., `10`).
///
/// # Notes
///
/// - The `create_pool` method initializes the connection pool with the specified configuration.
/// - The `NoTls` argument specifies that no TLS encryption is used for the database connection. If you need TLS, you should configure it accordingly.
pub struct Redis {}

impl Redis {
    /// Initialize a connection pool to the Redis database.
    ///
    /// # Purpose
    ///
    /// The purpose of this method is to set an key -> value pair in the Redis database.
    ///
    /// # Returns
    ///
    /// A `Pool` instance that can be used to manage database connections.
    pub async fn set(redis_pool: &Pool, key: &str, value: &str) -> RedisResult<()> {
        let mut redis_conn = redis_pool.get().await.unwrap();
        cmd("SET")
            .arg(&[key, value])
            .query_async::<_, ()>(&mut redis_conn)
            .await
    }

    /// Initialize a connection pool to the Redis database.
    ///
    /// # Purpose
    ///
    /// The purpose of this method is to get an key -> value pair in the Redis database.
    ///
    /// # Returns
    ///
    /// A `Pool` instance that can be used to manage database connections.
    pub async fn get(redis_pool: &Pool, key: &str) -> RedisResult<String> {
        let mut redis_conn = redis_pool.get().await.unwrap();
        cmd("GET")
            .arg(&[key])
            .query_async::<_, String>(&mut redis_conn)
            .await
    }

    /// Initialize a connection pool to the Redis database.
    ///
    /// # Purpose
    ///
    /// The purpose of this method is to delete an key -> value pair in the Redis database.
    ///
    /// # Returns
    ///
    /// A `Pool` instance that can be used to manage database connections.
    pub async fn delete(redis_pool: &Pool, key: &str) -> RedisResult<i32> {
        let mut redis_conn = redis_pool.get().await.unwrap();
        cmd("DEL")
            .arg(&[key])
            .query_async::<_, i32>(&mut redis_conn)
            .await
    }

    /// Redis Success model
    ///
    /// It creates a Success Redis Pool Connection.
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to guarantee that Redis is available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::infra::redis::Redis;
    ///
    /// let pool = Redis::pool();
    /// ```
    pub async fn pool() -> Pool {
        let mut cfg = Config::default();
        cfg.connection = Some(ConnectionInfo {
            addr: ConnectionAddr::Tcp(
                env::var("REDIS_HOST").unwrap(),
                env::var("REDIS_PORT").unwrap().parse().unwrap(),
            ),
            redis: RedisConnectionInfo {
                db: env::var("REDIS_NUMBER").unwrap().parse().unwrap(),
                username: Some(env::var("REDIS_USER").unwrap()),
                password: Some(env::var("REDIS_PASSWORD").unwrap()),
            },
        });
        cfg.pool = Some(PoolConfig {
            max_size: env::var("REDIS_POOL_SIZE").unwrap().parse().unwrap(),
            timeouts: Timeouts {
                wait: Some(Duration::from_secs(60)),
                create: Some(Duration::from_secs(60)),
                recycle: Some(Duration::from_secs(60)),
            },
            queue_mode: Config::get_pool_config(&cfg).queue_mode,
        });
        cfg.create_pool(Some(Runtime::Tokio1)).unwrap()
    }
}
