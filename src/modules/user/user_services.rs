use super::{
    user_dtos::{CreateUserDTO, LoginUserDTO, UserDTO},
    user_queues::CreateUserAppQueue,
    user_repositories::{get_user_salt_repository, insert_user_repository, login_user_repository},
};
use crate::shared::{
    exceptions::custom_error_to_io_error_kind::{custom_error_to_io_error_kind, CustomError},
    structs::jwt_claims::Claims,
};
use actix_web::web::{Data, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::{env, sync::Arc};

pub async fn insert_user_service(
    queue: Data<Arc<CreateUserAppQueue>>,
    pool: Data<deadpool_postgres::Pool>,
    mut body: Json<CreateUserDTO>,
    user_id: String,
) -> Result<UserDTO, std::io::Error> {
    body.password = match hash(&body.password, DEFAULT_COST - 4) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::Bcrypt),
                e,
            ))
        }
    };
    let user_salt = uuid::Uuid::new_v4().to_string();
    body.password = format!("{}{}", body.password, user_salt);

    match insert_user_repository(queue.clone(), pool, body, user_id, user_salt).await {
        Ok(user) => Ok(user),
        Err(e) => Err(std::io::Error::new(e.kind(), e)),
    }
}

pub struct LoginUserServiceResponse {
    pub refresh_token: String,
    pub access_token: String,
}

pub async fn login_user_service(
    body: Json<LoginUserDTO>,
    pool: Data<deadpool_postgres::Pool>,
) -> Result<LoginUserServiceResponse, std::io::Error> {
    match login_user_repository(body.email.clone(), pool.clone()).await {
        Ok(repository_response) => {
            let user_salt = match get_user_salt_repository(
                repository_response.id.clone(),
                pool.clone(),
            )
            .await
            {
                Ok(user_salt) => user_salt,
                Err(e) => return Err(std::io::Error::new(e.kind(), e)),
            };
            let password_without_salt = match repository_response.password.strip_suffix(&user_salt)
            {
                Some(password) => password,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Falha ao retirar o salt da senha.",
                    ))
                }
            };
            match verify(body.password.clone(), &password_without_salt) {
                Ok(true) => {
                    let mut claims = Claims {
                        sub: repository_response.id.clone(),
                        role: String::from("admin"),
                        exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
                    };
                    let refresh_token = match jsonwebtoken::encode(
                        &jsonwebtoken::Header::default(),
                        &claims,
                        &jsonwebtoken::EncodingKey::from_secret(
                            env::var("JWT_KEY").unwrap().as_ref(),
                        ),
                    ) {
                        Ok(token) => token,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                custom_error_to_io_error_kind(CustomError::JWTError),
                                e,
                            ))
                        }
                    };
                    claims.exp =
                        (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp() as usize;
                    let access_token = match jsonwebtoken::encode(
                        &jsonwebtoken::Header::default(),
                        &claims,
                        &jsonwebtoken::EncodingKey::from_secret(
                            env::var("JWT_KEY2").unwrap().as_ref(),
                        ),
                    ) {
                        Ok(token) => token,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                custom_error_to_io_error_kind(CustomError::JWTError),
                                e,
                            ))
                        }
                    };
                    Ok(LoginUserServiceResponse {
                        refresh_token,
                        access_token,
                    })
                }
                Ok(false) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "E-mail e/ou senha incorretos.",
                )),
                Err(e) => Err(std::io::Error::new(
                    custom_error_to_io_error_kind(CustomError::Bcrypt),
                    e,
                )),
            }
        }
        Err(e) => Err(std::io::Error::new(e.kind().clone(), e)),
    }
}
