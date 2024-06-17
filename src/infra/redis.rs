use deadpool_redis::{
    redis::{cmd, RedisResult},
    Config, ConnectionAddr, ConnectionInfo, Pool, PoolConfig, RedisConnectionInfo, Runtime,
    Timeouts,
};
use std::{env, time::Duration};

pub struct Redis {}

impl Redis {
    pub async fn set_redis(redis_pool: &Pool, key: &str, value: &str) -> RedisResult<()> {
        let mut redis_conn = redis_pool.get().await.unwrap();
        cmd("SET")
            .arg(&[key, value])
            .query_async::<_, ()>(&mut redis_conn)
            .await
    }

    pub async fn get_redis(redis_pool: &Pool, key: &str) -> RedisResult<String> {
        let mut redis_conn = redis_pool.get().await.unwrap();
        cmd("GET")
            .arg(&[key])
            .query_async::<_, String>(&mut redis_conn)
            .await
    }

    pub async fn pool() -> Pool {
        let mut cfg = Config::default();
        cfg.connection = Some(ConnectionInfo {
            addr: ConnectionAddr::Tcp(
                env::var("REDIS_HOST").unwrap(),
                env::var("REDIS_PORT").unwrap().parse().unwrap(),
            ),
            redis: RedisConnectionInfo {
                db: 0,
                username: None,
                password: None,
            },
        });
        cfg.pool = Some(PoolConfig {
            max_size: 9995,
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
