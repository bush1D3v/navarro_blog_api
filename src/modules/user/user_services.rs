use super::{
    user_dtos::{CreateUserDTO, DetailUserDTO, LoginUserDTO, UserDTO},
    user_providers::{email_exists, email_not_exists},
    user_queues::CreateUserAppQueue,
    user_repositories::*,
};
use crate::shared::{
    structs::query_params::QueryParams,
    treaties::{
        bcrypt_treated::{Bcrypt, BcryptVerifyData},
        jwt_treated::Jwt,
        strip_suffix_treated::StripSuffix,
    },
};
use actix_web::{
    web::{Data, Json, Query},
    HttpResponse,
};
use std::sync::Arc;

pub async fn insert_user_service(
    queue: Data<Arc<CreateUserAppQueue>>,
    pg_pool: Data<deadpool_postgres::Pool>,
    mut body: Json<CreateUserDTO>,
) -> Result<UserDTO, HttpResponse> {
    match email_exists(pg_pool.clone(), body.email.clone()).await {
        Ok(_) => (),
        Err(e) => return Err(e),
    };
    let user_id = uuid::Uuid::new_v4().to_string();
    body.password = match Bcrypt::hash(&body.password) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    let user_salt = uuid::Uuid::new_v4().to_string();
    body.password = format!("{}{}", body.password, user_salt);

    match insert_user_repository(queue.clone(), pg_pool, body, user_id.clone(), user_salt).await {
        Ok(user) => Ok(UserDTO {
            id: user.id,
            name: user.name,
            email: user.email,
            password: user.password,
            created_at: user.created_at,
        }),
        Err(e) => Err(e),
    }
}

pub struct LoginUserServiceResponse {
    pub user: UserDTO,
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
            Err(e) => return Err(e),
        }
    }
    match login_user_repository(body.email.clone(), pg_pool.clone()).await {
        Ok(user) => {
            let user_salt = match get_user_salt_repository(user.id.clone(), pg_pool.clone()).await {
                Ok(user_salt) => user_salt,
                Err(e) => return Err(e),
            };
            let password_without_salt =
                match StripSuffix::strip_suffix(user.password.clone(), &user_salt) {
                    Ok(password_without_salt) => password_without_salt,
                    Err(e) => return Err(e),
                };
            match Bcrypt::verify(
                body.password.clone(),
                password_without_salt.as_str(),
                BcryptVerifyData::EmailPassword(body.email.clone(), body.password.clone()),
            ) {
                Ok(_) => {
                    let refresh_token = match Jwt::refresh_token_constructor(user.id.clone()) {
                        Ok(refresh_token) => refresh_token,
                        Err(e) => return Err(e),
                    };
                    let access_token = match Jwt::access_token_constructor(user.id.clone()) {
                        Ok(access_token) => access_token,
                        Err(e) => return Err(e),
                    };
                    Ok(LoginUserServiceResponse {
                        user,
                        refresh_token,
                        refresh_expires_in: 7 * 60 * 60 * 24,
                        access_token,
                        access_expires_in: 30 * 60,
                    })
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

pub async fn detail_user_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    user_id: String,
) -> Result<UserDTO, HttpResponse> {
    match detail_user_repository(pg_pool, user_id.clone()).await {
        Ok(user) => Ok(user),
        Err(e) => Err(e),
    }
}

pub async fn list_users_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    query_params: Query<QueryParams>,
) -> Result<Vec<DetailUserDTO>, HttpResponse> {
    match list_users_repository(pg_pool, query_params).await {
        Ok(user) => Ok(user),
        Err(e) => Err(e),
    }
}

pub struct DeleteUserServiceResponse {
    pub email: String,
}

pub async fn delete_user_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    user_password: String,
    user_id: String,
) -> Result<DeleteUserServiceResponse, HttpResponse> {
    let user = match detail_user_repository(pg_pool.clone(), user_id.clone()).await {
        Ok(user) => user,
        Err(e) => return Err(e),
    };
    let user_salt = match get_user_salt_repository(user_id.clone(), pg_pool.clone()).await {
        Ok(user_salt) => user_salt,
        Err(e) => return Err(e),
    };
    let hash = match StripSuffix::strip_suffix(user.password, &user_salt) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    return match Bcrypt::verify(
        user_password.clone(),
        hash.as_str(),
        BcryptVerifyData::Password(user_password),
    ) {
        Ok(_) => match delete_user_repository(pg_pool, user_id).await {
            Ok(_) => Ok(DeleteUserServiceResponse { email: user.email }),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
}
