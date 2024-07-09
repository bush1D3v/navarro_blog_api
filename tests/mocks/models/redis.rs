use deadpool_redis::{
    Config, ConnectionAddr, ConnectionInfo, Pool, PoolConfig, RedisConnectionInfo, Runtime,
    Timeouts,
};
use std::{env, time::Duration};

pub struct RedisModels {}

impl RedisModels {
    pub async fn pool_success() -> Pool {
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

    pub async fn pool_error() -> Pool {
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
