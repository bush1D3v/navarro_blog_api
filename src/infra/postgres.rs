use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use std::env;
use tokio_postgres::NoTls;

pub fn postgres() -> Pool {
    let mut cfg = Config::new();
    cfg.host = Some(
        env::var("DB_HOST")
            .unwrap_or("localhost".into())
            .to_string(),
    );
    cfg.port = Some(
        env::var("DB_PORT")
            .unwrap_or("5432".to_string())
            .parse()
            .unwrap_or(5432),
    );
    cfg.dbname = Some(env::var("DB_NAME").unwrap_or("blogdb".into()).to_string());
    cfg.user = Some(env::var("DB_USER").unwrap_or("postgres".into()).to_string());
    cfg.password = Some(
        env::var("DB_PASSWORD")
            .unwrap_or("220305".into())
            .to_string(),
    );

    let pool_size = env::var("POOL_SIZE")
        .unwrap_or("125".to_string())
        .parse::<usize>()
        .unwrap_or(125);

    cfg.pool = PoolConfig::new(pool_size).into();

    cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
}
