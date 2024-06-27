use super::{
    user_dtos::{CreateUserDTO, LoginUserDTO, UserDTO},
    user_providers::{email_exists, email_not_exists},
    user_queues::CreateUserAppQueue,
    user_repositories::{
        detail_user_repository, get_user_salt_repository, insert_user_repository,
        login_user_repository,
    },
};
use crate::{shared::structs::jwt_claims::Claims, utils::error_construct::error_construct};
use actix_web::{
    web::{Data, Json},
    HttpResponse,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::{env, io::ErrorKind, sync::Arc};

pub struct InsertUserServiceResponse {
    pub user: UserDTO,
    pub user_id: String,
}

pub async fn insert_user_service(
    queue: Data<Arc<CreateUserAppQueue>>,
    pg_pool: Data<deadpool_postgres::Pool>,
    mut body: Json<CreateUserDTO>,
) -> Result<InsertUserServiceResponse, HttpResponse> {
    match email_exists(pg_pool.clone(), body.email.clone()).await {
        Ok(_) => (),
        Err(e) => {
            return match e.kind() {
                ErrorKind::InvalidInput => Err(HttpResponse::Conflict().json(error_construct(
                    String::from("email"),
                    String::from("conflict"),
                    e.to_string(),
                    Some(body.email.clone()),
                    None,
                    None,
                ))),
                ErrorKind::ConnectionAborted => {
                    Err(HttpResponse::ServiceUnavailable().json(error_construct(
                        String::from("database"),
                        String::from("service unavailable"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    )))
                }
                _ => Err(HttpResponse::InternalServerError().json(error_construct(
                    String::from("server"),
                    String::from("internal server error"),
                    e.to_string(),
                    None,
                    None,
                    None,
                ))),
            }
        }
    };
    let user_id = uuid::Uuid::new_v4().to_string();
    body.password = match hash(&body.password, DEFAULT_COST - 4) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("bcrypt"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            )))
        }
    };
    let user_salt = uuid::Uuid::new_v4().to_string();
    body.password = format!("{}{}", body.password, user_salt);

    match insert_user_repository(queue.clone(), pg_pool, body, user_id.clone(), user_salt).await {
        Ok(user) => Ok(InsertUserServiceResponse { user, user_id }),
        Err(e) => match e.kind() {
            ErrorKind::InvalidInput => {
                Err(HttpResponse::InternalServerError().json(error_construct(
                    String::from("bcrypt"),
                    String::from("internal server error"),
                    e.to_string(),
                    None,
                    None,
                    None,
                )))
            }
            ErrorKind::ConnectionAborted => {
                Err(HttpResponse::ServiceUnavailable().json(error_construct(
                    String::from("database"),
                    String::from("service unavailable"),
                    e.to_string(),
                    None,
                    None,
                    None,
                )))
            }
            _ => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("server"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        },
    }
}

pub struct LoginUserServiceResponse {
    pub refresh_token: String,
    pub refresh_expires_in: i64,
    pub access_token: String,
    pub access_expires_in: i64,
}

pub async fn login_user_service(
    body: Json<LoginUserDTO>,
    pg_pool: Data<deadpool_postgres::Pool>,
    email_found_in_redis: bool,
) -> Result<LoginUserServiceResponse, HttpResponse> {
    if !email_found_in_redis {
        match email_not_exists(pg_pool.clone(), body.email.clone()).await {
            Ok(_) => (),
            Err(e) => {
                return match e.kind() {
                    ErrorKind::NotFound => Err(HttpResponse::NotFound().json(error_construct(
                        String::from("email"),
                        String::from("not found"),
                        e.to_string(),
                        Some(body.email.clone()),
                        None,
                        None,
                    ))),
                    ErrorKind::ConnectionAborted => {
                        Err(HttpResponse::ServiceUnavailable().json(error_construct(
                            String::from("database"),
                            String::from("service unavailable"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        )))
                    }
                    _ => Err(HttpResponse::InternalServerError().json(error_construct(
                        String::from("server"),
                        String::from("internal server error"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    ))),
                }
            }
        }
    }
    match login_user_repository(body.email.clone(), pg_pool.clone()).await {
        Ok(repository_response) => {
            let user_salt =
                match get_user_salt_repository(repository_response.id.clone(), pg_pool.clone())
                    .await
                {
                    Ok(user_salt) => user_salt,
                    Err(e) => {
                        return match e.kind() {
                            ErrorKind::ConnectionAborted => Err(HttpResponse::ServiceUnavailable()
                                .json(error_construct(
                                    String::from("database"),
                                    String::from("service unavailable"),
                                    e.to_string(),
                                    None,
                                    None,
                                    None,
                                ))),
                            _ => Err(HttpResponse::InternalServerError().json(error_construct(
                                String::from("server"),
                                String::from("internal server error"),
                                e.to_string(),
                                None,
                                None,
                                None,
                            ))),
                        }
                    }
                };
            let password_without_salt = match repository_response.password.strip_suffix(&user_salt)
            {
                Some(password) => password,
                None => {
                    return Err(HttpResponse::InternalServerError().json(error_construct(
                        String::from("server"),
                        String::from("internal server error"),
                        String::from("Erro ao extrair o salt do usuário."),
                        None,
                        None,
                        None,
                    )))
                }
            };
            match verify(body.password.clone(), password_without_salt) {
                Ok(true) => {
                    let refresh_expires_in: i64 = 7;
                    let mut claims = Claims {
                        sub: repository_response.id.clone(),
                        role: String::from("admin"),
                        exp: (chrono::Utc::now() + chrono::Duration::days(refresh_expires_in))
                            .timestamp() as usize,
                    };
                    let refresh_token = match jsonwebtoken::encode(
                        &jsonwebtoken::Header::default(),
                        &claims,
                        &jsonwebtoken::EncodingKey::from_secret(
                            env::var("JWT_REFRESH_KEY").unwrap().as_ref(),
                        ),
                    ) {
                        Ok(token) => token,
                        Err(e) => {
                            return Err(HttpResponse::InternalServerError().json(error_construct(
                                String::from("jsonwebtoken"),
                                String::from("internal server error"),
                                e.to_string(),
                                None,
                                None,
                                None,
                            )))
                        }
                    };
                    let access_expires_in: i64 = 30;
                    claims.exp =
                        (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp() as usize;
                    let access_token = match jsonwebtoken::encode(
                        &jsonwebtoken::Header::default(),
                        &claims,
                        &jsonwebtoken::EncodingKey::from_secret(
                            env::var("JWT_ACCESS_KEY").unwrap().as_ref(),
                        ),
                    ) {
                        Ok(token) => token,
                        Err(e) => {
                            return Err(HttpResponse::InternalServerError().json(error_construct(
                                String::from("jsonwebtoken"),
                                String::from("internal server error"),
                                e.to_string(),
                                None,
                                None,
                                None,
                            )))
                        }
                    };
                    Ok(LoginUserServiceResponse {
                        refresh_token,
                        refresh_expires_in: refresh_expires_in * 60 * 60 * 24,
                        access_token,
                        access_expires_in: access_expires_in * 60,
                    })
                }
                Ok(false) => Err(HttpResponse::Unauthorized().json(error_construct(
                    String::from("email/password"),
                    String::from("unauthorized"),
                    String::from("E-mail e/ou senha incorretos."),
                    None,
                    None,
                    None,
                ))),
                Err(e) => Err(HttpResponse::InternalServerError().json(error_construct(
                    String::from("bcrypt"),
                    String::from("internal server error"),
                    e.to_string(),
                    None,
                    None,
                    None,
                ))),
            }
        }
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Err(HttpResponse::NotFound().json(error_construct(
                String::from("user"),
                String::from("not found"),
                e.to_string(),
                Some(body.email.clone()),
                None,
                None,
            ))),
            ErrorKind::ConnectionAborted => {
                Err(HttpResponse::ServiceUnavailable().json(error_construct(
                    String::from("database"),
                    String::from("service unavailable"),
                    e.to_string(),
                    None,
                    None,
                    None,
                )))
            }
            _ => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("database"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        },
    }
}

pub async fn detail_user_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    user_id: String,
) -> Result<UserDTO, HttpResponse> {
    match detail_user_repository(pg_pool, user_id.clone()).await {
        Ok(user) => Ok(user),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Err(HttpResponse::NotFound().json(error_construct(
                String::from("user"),
                String::from("not found"),
                e.to_string(),
                Some(user_id),
                None,
                None,
            ))),
            ErrorKind::ConnectionAborted => {
                Err(HttpResponse::ServiceUnavailable().json(error_construct(
                    String::from("database"),
                    String::from("service unavailable"),
                    e.to_string(),
                    None,
                    None,
                    None,
                )))
            }
            _ => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("database"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        },
    }
}
