use super::{
    user_dtos::{DetailUserDTO, InsertUserDTO, LoginUserDTO, PutUserDTO, UserDTO},
    user_providers::{email_exists, email_not_exists},
    user_queues::{DeleteUserAppQueue, InsertUserAppQueue, PutUserAppQueue},
    user_repositories::*,
    user_serdes::UserSerdes,
};
use crate::{
    shared::{
        structs::query_params::QueryParams,
        treaties::{
            bcrypt_treated::{Bcrypt, BcryptVerifyData},
            jwt_treated::Jwt,
            strip_suffix_treated::StripSuffix,
        },
    },
    utils::{error_construct::error_construct, password_verifier::password_verifier},
};
use actix_web::{
    web::{Data, Json, Query},
    HttpResponse,
};
use std::sync::Arc;

pub async fn insert_user_service(
    queue: Data<Arc<InsertUserAppQueue>>,
    pg_pool: Data<deadpool_postgres::Pool>,
    mut body: Json<InsertUserDTO>,
) -> Result<UserDTO, HttpResponse> {
    match email_exists(pg_pool, body.email.clone()).await {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let hash = match Bcrypt::hash(&body.password) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    let user_salt = uuid::Uuid::new_v4().to_string();
    body.password = format!("{}{}", hash, user_salt);

    match insert_user_repository(queue.clone(), body, user_id.clone(), user_salt).await {
        Ok(user) => Ok(user),
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

    let user_dto = match login_user_repository(body.email.clone(), pg_pool.clone()).await {
        Ok(user) => user,
        Err(e) => return Err(e),
    };

    let user_salt = match get_user_salt_repository(user_dto.id.clone(), pg_pool.clone()).await {
        Ok(user_salt) => user_salt,
        Err(e) => return Err(e),
    };

    let password_without_salt =
        match StripSuffix::strip_suffix(user_dto.password.clone(), &user_salt) {
            Ok(password_without_salt) => password_without_salt,
            Err(e) => return Err(e),
        };

    match Bcrypt::verify(
        body.password.clone(),
        &password_without_salt,
        BcryptVerifyData::EmailPassword(body.email.clone(), body.password.clone()),
    ) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    let refresh_token = match Jwt::refresh_token_constructor(user_dto.id.clone()) {
        Ok(refresh_token) => refresh_token,
        Err(e) => return Err(e),
    };
    let access_token = match Jwt::access_token_constructor(user_dto.id.clone()) {
        Ok(access_token) => access_token,
        Err(e) => return Err(e),
    };
    Ok(LoginUserServiceResponse {
        user: user_dto,
        refresh_token,
        refresh_expires_in: 7 * 60 * 60 * 24,
        access_token,
        access_expires_in: 30 * 60,
    })
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

pub async fn delete_user_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    queue: Data<Arc<DeleteUserAppQueue>>,
    user_password: String,
    user_id: String,
    string_user: Option<String>,
) -> Result<String, HttpResponse> {
    let db_user: UserDTO = if string_user.is_none() {
        match detail_user_repository(pg_pool.clone(), user_id.clone()).await {
            Ok(user_dto) => user_dto,
            Err(e) => return Err(e),
        }
    } else {
        match UserSerdes::serde_string_to_json(&string_user.unwrap()) {
            Ok(user_dto) => user_dto,
            Err(e) => return Err(e),
        }
    };

    match password_verifier(
        pg_pool,
        user_id.clone(),
        db_user.password,
        user_password.clone(),
        BcryptVerifyData::Password(user_password),
    )
    .await
    {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    match delete_user_repository(queue, user_id).await {
        Ok(_) => Ok(db_user.email),
        Err(e) => Err(e),
    }
}

pub async fn put_user_service(
    pg_pool: Data<deadpool_postgres::Pool>,
    queue: Data<Arc<PutUserAppQueue>>,
    mut body: PutUserDTO,
    user_id: String,
    string_user: Option<String>,
) -> Result<UserDTO, HttpResponse> {
    match email_exists(pg_pool.clone(), body.new_email.clone()).await {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    let mut db_user: UserDTO = if string_user.is_none() {
        match detail_user_repository(pg_pool.clone(), user_id.clone()).await {
            Ok(user_dto) => user_dto,
            Err(e) => return Err(e),
        }
    } else {
        match UserSerdes::serde_string_to_json(&string_user.unwrap()) {
            Ok(user_dto) => user_dto,
            Err(e) => return Err(e),
        }
    };

    if db_user.email != body.email {
        return Err(HttpResponse::Forbidden().json(error_construct(
            String::from("user"),
            String::from("forbidden"),
            String::from(
                "Você não tem permissão para alterar informações associadas a um e-mail que não está vinculado ao seu ID de usuário.",
            ),
            Some(body.email),
            None,
            None,
        )));
    }

    let salt = match password_verifier(
        pg_pool.clone(),
        user_id.clone(),
        db_user.password.clone(),
        body.password.clone(),
        BcryptVerifyData::Password(body.password.clone()),
    )
    .await
    {
        Ok(salt) => salt,
        Err(e) => return Err(e),
    };

    body.new_password = match Bcrypt::hash(&body.new_password) {
        Ok(hash) => format!("{}{}", hash, salt),
        Err(e) => return Err(e),
    };

    match put_user_repository(queue, Json(body.clone()), user_id).await {
        Ok(updated_at) => {
            db_user.updated_at = Some(updated_at);
            db_user.email = body.new_email;
            db_user.password = body.new_password;
            Ok(db_user)
        }
        Err(e) => Err(e),
    }
}
