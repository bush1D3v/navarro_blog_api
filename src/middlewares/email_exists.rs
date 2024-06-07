use crate::{
    dtos::user::CreateUserDTO,
    exceptions::custom_error_to_io_error_kind::{custom_error_to_io_error_kind, CustomError},
};
use actix_web::web::{self, Json};
use deadpool_postgres::Pool;

pub async fn email_exists<'a>(
    pool: &'a web::Data<Pool>,
    body: &'a web::Json<CreateUserDTO>,
) -> Result<&'a Json<CreateUserDTO>, std::io::Error> {
    let email = body.email.clone();
    let conn = match pool.get().await {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::PoolError(&e)),
                e,
            ))
        }
    };
    let stmt = match conn.prepare("SELECT id FROM users WHERE email = $1").await {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::TokioPostgres(&e)),
                e,
            ))
        }
    };
    let rows = match conn.query(&stmt, &[&email]).await {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::TokioPostgres(&e)),
                e,
            ))
        }
    };
    if rows.len() > 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Este e-mail já está sendo utilizado por outro usuário.",
        ));
    }
    Ok(body)
}
