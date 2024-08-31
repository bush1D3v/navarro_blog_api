use deadpool_redis::{
    Config, ConnectionAddr, ConnectionInfo, Pool, PoolConfig, RedisConnectionInfo, Runtime,
    Timeouts,
};
use std::{env, time::Duration};

/// Models for Redis
///
/// It contains the Redis Pool Connection models.
///
/// # Functions
///
/// - `postgres_success()` - It creates a Success Redis Pool Connection.
/// - `postgres_error()` - It creates a Error Redis Pool Connection.
pub struct RedisModels {}

impl RedisModels {
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
    /// use navarro_blog_api::mocks::models::redis::RedisModels;
    ///
    /// let pool = RedisModels::redis_success();
    /// ```
    pub async fn redis_success() -> Pool {
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

    /// Redis Error model
    ///
    /// It creates a Error Redis Pool Connection.
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to throw a redis connection error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::redis::RedisModels;
    ///
    /// let pool = RedisModels::redis_error();
    /// ```
    pub async fn redis_error() -> Pool {
        let mut cfg = Config::default();
        cfg.connection = Some(ConnectionInfo {
            addr: ConnectionAddr::Tcp(
                env::var("6380").unwrap(),
                env::var("1.1.1.1").unwrap().parse().unwrap(),
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
