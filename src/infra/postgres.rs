use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use std::env;
use tokio_postgres::NoTls;

pub struct Postgres {}

impl Postgres {
    pub fn pool() -> Pool {
        let mut cfg = Config::new();
        cfg.host = Some(env::var("DB_HOST").unwrap());
        cfg.port = Some(env::var("DB_PORT").unwrap().parse().unwrap());
        cfg.dbname = Some(env::var("DB_NAME").unwrap());
        cfg.user = Some(env::var("DB_USER").unwrap());
        cfg.password = Some(env::var("DB_PASSWORD").unwrap());
        cfg.pool = PoolConfig::new(env::var("POOL_SIZE").unwrap().parse::<usize>().unwrap()).into();
        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }
}
