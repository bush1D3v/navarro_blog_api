use super::{
    user_dtos::*,
    user_queues::{InsertUserAppQueue, PutUserAppQueue},
    user_serdes::UserSerdes,
    user_services::*,
};
use crate::{
    infra::redis::Redis,
    middlewares::{auth_middleware::auth_middleware, jwt_token_middleware::jwt_token_middleware},
    modules::user::{
        user_queues::DeleteUserAppQueue,
        user_services::{delete_user_service, login_user_service},
    },
    shared::structs::query_params::QueryParams,
    utils::validate_body_error::validate_body_error,
};
use actix_web::{
    body::BoxBody, delete, get, options, post, put, web, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

pub fn user_controllers_module() -> actix_web::Scope {
    web::scope("/user")
        .service(user_options)
        .service(insert_user)
        .service(login_user)
        .service(list_users)
        .service(user_id_options)
        .service(detail_user)
        .service(put_user)
        .service(delete_user)
}

#[utoipa::path(
	tag = "user",
    path = "/user",
	request_body = InsertUserDTO,
	responses((
		status = 201, description = "Insere um novo usuário (Created)", headers((
			"location" = String, description = "Link para realizar get de dados do usuário inserido"
		)),
	), (
		status = 400, description = "Erro do usuário, por falta de preenchimento de campo ou inválido (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "password": [{
                "code": "length",
                "message": "A senha deve ter pelo menos 8 caracteres.",
                "params": {
                    "min": 8,
                    "value": "senha12",
                    "max": 255
                }
		    }]
        })
	), (
		status = 422, description = "Erro do usuário, por campo com formato inválido (Unprocessable Entity)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "code": "regex",
            "message": "O e-mail deve ser um endereço válido.",
            "params": {
                "value": "teste34gmail.com"
            }
        })
	), (
		status = 409, description = "Conflito com recurso já no servidor (Conflict)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "email": [{
                "code": "conflict",
                "message": "Este e-mail já está sendo utilizado por outro usuário.",
                "params": {
                    "min": null,
                    "value": "teste@gmail.com",
                    "max": null,
                }
		    }]
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "bcrypt": [{
                "code": "internal server error",
                "message": "bcrypt: hash creation failed",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[post("")]
pub async fn insert_user(
    body: web::Json<InsertUserDTO>,
    queue: web::Data<Arc<InsertUserAppQueue>>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    postgres_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => (),
        Err(e) => return validate_body_error(e.field_errors()),
    };
    let redis_user = match Redis::get(&redis_pool, &body.email.clone()).await {
        Ok(redis_user) => redis_user,
        Err(_) => String::from(""),
    };
    match insert_user_service(queue.clone(), postgres_pool, body, redis_user).await {
        Ok(resp) => match UserSerdes::serde_json_to_string(&resp) {
            Ok(redis_user) => {
                let _ = Redis::set(&redis_pool, &resp.id, &redis_user).await;
                let _ = Redis::set(&redis_pool, &resp.email, &redis_user).await;
                HttpResponse::Created()
                    .append_header(("Location", format!("/user/{}", resp.id)))
                    .finish()
            }
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[utoipa::path(
	tag = "user",
    path = "/user/login",
	request_body = LoginUserDTO,
	responses((
		status = 200, description = "Usuário logado com sucesso (OK)", body = LoginUserServiceResponse,
		content_type = "application/json", example = json ! ({
			"access_token": "string",
            "access_expires_in": "i64",
			"refresh_token": "string",
            "refresh_expires_in": "i64"
        })
	), (
		status = 400, description = "Erro do usuário por campo inválido e/ou falta de preenchimento (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "password": [{
                "code": "length",
                "message": "A senha deve ter pelo menos 8 caracteres.",
                "params": {
                    "min": 8,
                    "value": "senha",
                    "max": 255
                }
            }]
        })
	), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "password": [{
                "code": "unauthorized",
                "message": "E-mail e/ou senha incorretos.",
                "params": {
                    "min": null,
                    "value": "Senha123",
                    "max": null
                }
		    }]
        })
	), (
		status = 404, description = "Usuário não encontrado (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "email": [{
                "code": "not found",
                "message": "Não foi encontrado um usuário com este e-mail.",
                "params": {
                    "min": null,
                    "value": "teste@gmail.com",
                    "max": null
                }
		    }]
        })
	), (
		status = 422, description = "Erro do usuário, por campo com formato inválido (Unprocessable Entity)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "code": "regex",
            "message": "O e-mail deve ser um endereço válido.",
            "params": {
                "value": "teste34gmail.com"
            }
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "bcrypt": [{
                "code": "internal server error",
                "message": "bcrypt: hash creation failed",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[post("login")]
pub async fn login_user(
    body: web::Json<LoginUserDTO>,
    postgres_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => (),
        Err(e) => return validate_body_error(e.field_errors()),
    };
    let redis_user = match Redis::get(&redis_pool, &body.email).await {
        Ok(redis_user) => redis_user,
        Err(_) => String::from(""),
    };
    match login_user_service(body.clone(), postgres_pool, redis_user.clone()).await {
        Ok(service_resp) => {
            login_user_response_constructor(service_resp, &redis_pool, &redis_user, &body.email)
                .await
        }
        Err(e) => e,
    }
}

#[derive(Serialize, Deserialize)]
struct LoginUserControllerResponse {
    pub access_token: String,
    pub access_expires_in: i64,
    pub refresh_token: String,
    pub refresh_expires_in: i64,
}

async fn login_user_response_constructor(
    service_resp: LoginUserServiceResponse,
    redis_pool: &deadpool_redis::Pool,
    redis_user: &str,
    email: &str,
) -> HttpResponse<BoxBody> {
    let _ = Redis::set(redis_pool, &service_resp.user.id, redis_user).await;
    let _ = Redis::set(redis_pool, email, redis_user).await;
    HttpResponse::Ok().json(LoginUserControllerResponse {
        access_token: service_resp.access_token,
        access_expires_in: service_resp.access_expires_in,
        refresh_token: service_resp.refresh_token,
        refresh_expires_in: service_resp.refresh_expires_in,
    })
}

#[utoipa::path(
    tag = "user",
    path = "/user",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("offset" = Option<i8>, Query, description = "Paginação (offset)"),
        ("limit" = Option<i8>, Query, description = "Paginação (limit)"),
        ("order_by" = Option<String>, Query, description = "Coluna de ordenação"),
        ("order_direction" = Option<String>, Query, description = "Direção da ordenação")
    ),
    responses((
        status = 200, description = "Listagem de usuários com sucesso (OK)", body = Vec<DetailUserDTO>,
        content_type = "application/json", example = json ! ([
                {
                    "id": "f5d46b1b-6adb-40ac-82d6-b0006cf781c0",
                    "name": "borrow lightning",
                    "email": "lightning@gmail.com",
                    "created_at": "2024-06-18 22:03:54.053147-03",
                },
                {
                    "id": "f5d46b1b-6adb-40ac-82d6-b0006cf781c1",
                    "name": "borrow lightning2",
                    "email": "lightning2@gmail.com",
                    "created_at": "2024-06-18 22:03:54.053147-02",
                }
        ])
    ), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	), (
		status = 404, description = "Usuários não encontrados (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "id": [{
                "code": "not found",
                "message": "Não foram encontrados usuários.",
                "params": {
                    "min": null,
                    "value": "06buff3f-637d-4c15-a02c-c8247ffb9400",
                    "max": null
                }
		    }]
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "jsonwebtoken": [{
                "code": "internal server error",
                "message": "failed to decode token",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[get("")]
pub async fn list_users(
    postgres_pool: web::Data<deadpool_postgres::Pool>,
    req: HttpRequest,
    query_params: web::Query<QueryParams>,
) -> impl Responder {
    match jwt_token_middleware(req.headers()) {
        Ok(_) => (),
        Err(e) => return e,
    };
    match list_users_service(postgres_pool, query_params).await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => e,
    }
}

#[utoipa::path(
    tag = "user",
    path = "/user/{user_id}",
    security(("bearer_auth" = [])),
    responses((
        status = 200, description = "Detalhamento de usuário com sucesso (OK)", body = DetailUserDTO,
        content_type = "application/json", example = json ! ({
            "id": "f5d46b1b-6adb-40ac-82d6-b0006cf781c0",
            "name": "borrow lightning",
            "email": "lightning@gmail.com",
            "created_at": "2024-06-18 22:03:54.053147-03",
            "updated_at": "2024-06-22 18:03:54.053147-03"
        })
    ), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	) , (
		status = 404, description = "Usuário não encontrado (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "id": [{
                "code": "not found",
                "message": "Não foi encontrado um usuário com este id.",
                "params": {
                    "min": null,
                    "value": "06buff3f-637d-4c15-a02c-c8247ffb9400",
                    "max": null
                }
		    }]
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "jsonwebtoken": [{
                "code": "internal server error",
                "message": "failed to decode token",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[get("{user_id}")]
pub async fn detail_user(
    postgres_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    match auth_middleware(user_id.clone(), req, "user_id").await {
        Ok(_) => (),
        Err(e) => return e,
    };
    let redis_user = match Redis::get(&redis_pool, &user_id).await {
        Ok(redis_user) => redis_user,
        Err(_) => String::from(""),
    };
    match detail_user_service(postgres_pool, user_id.clone(), redis_user).await {
        Ok(user_dto) => match UserSerdes::serde_json_to_string(&user_dto) {
            Ok(redis_user) => {
                let _ = Redis::set(&redis_pool, &user_id, &redis_user).await;
                let _ = Redis::set(&redis_pool, &user_dto.email, &redis_user).await;
                let user = DetailUserDTO {
                    id: user_dto.id,
                    name: user_dto.name,
                    email: user_dto.email,
                    created_at: user_dto.created_at,
                    updated_at: user_dto.updated_at,
                };
                HttpResponse::Ok().json(user)
            }
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[utoipa::path(
    tag = "user",
    path = "/user/{user_id}",
    security(("bearer_auth" = [])),
    responses((
        status = 202, description = "Requisição aceita (Accepted)"
    ), (
		status = 400, description = "Erro do usuário por id inválido e/ou falta de preenchimento (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "user_id": [{
                "code": "bad request",
                "message": "A senha deve ter pelo menos 8 caracteres.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	) , (
		status = 404, description = "Usuário não encontrado (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "id": [{
                "code": "not found",
                "message": "Não foi encontrado um usuário com este id.",
                "params": {
                    "min": null,
                    "value": "06buff3f-637d-4c15-a02c-c8247ffb9400",
                    "max": null
                }
		    }]
        })
	), (
		status = 422, description = "Erro do usuário, por campo com formato inválido (Unprocessable Entity)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "code": "regex",
            "message": "O e-mail deve ser um endereço válido.",
            "params": {
                "value": "teste34gmail.com"
            }
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "jsonwebtoken": [{
                "code": "internal server error",
                "message": "failed to decode token",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[delete("{user_id}")]
pub async fn delete_user(
    postgres_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    queue: web::Data<Arc<DeleteUserAppQueue>>,
    body: web::Json<DeleteUserDTO>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    match auth_middleware(user_id.clone(), req, "user_id").await {
        Ok(_) => (),
        Err(e) => return e,
    };
    match body.validate() {
        Ok(_) => (),
        Err(e) => return validate_body_error(e.field_errors()),
    };
    let redis_user = match Redis::get(&redis_pool, &user_id).await {
        Ok(redis_user) => redis_user,
        Err(_) => String::from(""),
    };
    match delete_user_service(
        postgres_pool,
        queue,
        body.password.clone(),
        user_id.clone(),
        redis_user,
    )
    .await
    {
        Ok(email) => delete_user_response_constructor(&redis_pool, &user_id, &email).await,
        Err(e) => e,
    }
}

async fn delete_user_response_constructor(
    redis_pool: &deadpool_redis::Pool,
    user_id: &str,
    email: &str,
) -> HttpResponse {
    let _ = Redis::delete(redis_pool, user_id).await;
    let _ = Redis::delete(redis_pool, email).await;
    HttpResponse::Accepted().finish()
}

#[utoipa::path(
    tag = "user",
    path = "/user/{user_id}",
    security(("bearer_auth" = [])),
    responses((
        status = 202, description = "Requisição aceita (Accepted)", headers((
			"location" = String, description = "Link para realizar get de dados do usuário atualizado"
		))
    ), (
		status = 400, description = "Erro do usuário por id inválido e/ou falta de preenchimento (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "user_id": [{
                "code": "bad request",
                "message": "A senha deve ter pelo menos 8 caracteres.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	), (
		status = 403, description = "Acesso negado (Forbidden)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "user": [{
                "code": "forbidden",
                "message": "Você não tem permissão para alterar informações associadas a um e-mail que não está vinculado ao seu ID de usuário.",
                "params": {
                    "min": null,
                    "value": "teste@gmail.com",
                    "max": null
                }
		    }]
        })
	), (
		status = 404, description = "Usuário não encontrado (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "id": [{
                "code": "not found",
                "message": "Não foi encontrado um usuário com este id.",
                "params": {
                    "min": null,
                    "value": "06buff3f-637d-4c15-a02c-c8247ffb9400",
                    "max": null
                }
		    }]
        })
	),(
		status = 409, description = "Conflito com recurso já no servidor (Conflict)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "email": [{
                "code": "conflict",
                "message": "Este e-mail já está sendo utilizado por outro usuário.",
                "params": {
                    "min": null,
                    "value": "teste@gmail.com",
                    "max": null,
                }
		    }]
        })
	), (
		status = 422, description = "Erro do usuário, por campo com formato inválido (Unprocessable Entity)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "code": "regex",
            "message": "O e-mail deve ser um endereço válido.",
            "params": {
                "value": "teste34gmail.com"
            }
        })
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "jsonwebtoken": [{
                "code": "internal server error",
                "message": "failed to decode token",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({
            "database": [{
                "code": "service unavailable",
                "message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null,
                }
		    }]
        })
	))
)]
#[put("{user_id}")]
pub async fn put_user(
    postgres_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    queue: web::Data<Arc<PutUserAppQueue>>,
    body: web::Json<PutUserDTO>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    match auth_middleware(user_id.clone(), req, "user_id").await {
        Ok(_) => (),
        Err(e) => return e,
    };
    match body.validate() {
        Ok(_) => (),
        Err(e) => return validate_body_error(e.field_errors()),
    };
    let redis_user = match Redis::get(&redis_pool, &body.new_email).await {
        Ok(redis_user) => redis_user,
        Err(_) => String::from(""),
    };
    let service_response = match put_user_service(
        postgres_pool,
        queue,
        body.clone(),
        user_id.clone(),
        redis_user,
    )
    .await
    {
        Ok(service_resp) => service_resp,
        Err(e) => return e,
    };
    match UserSerdes::serde_json_to_string(&service_response) {
        Ok(redis_user) => {
            put_user_response_constructor(
                &redis_pool,
                &service_response.id,
                &body.email,
                &redis_user,
                &body.new_email,
            )
            .await
        }
        Err(e) => e,
    }
}

async fn put_user_response_constructor(
    redis_pool: &deadpool_redis::Pool,
    user_id: &str,
    excluded_email: &str,
    redis_user: &str,
    new_email: &str,
) -> HttpResponse {
    let _ = Redis::delete(redis_pool, excluded_email).await;
    let _ = Redis::set(redis_pool, user_id, redis_user).await;
    let _ = Redis::set(redis_pool, new_email, redis_user).await;
    HttpResponse::Accepted()
        .append_header(("Location", format!("/user/{}", user_id)))
        .finish()
}

#[utoipa::path(
    tag = "user",
    path = "/user",
    security(("bearer_auth" = [])),
    responses((
        status = 200, headers((
            "access-control-allow-methods" = Vec<String>, description = "Métodos HTTP suportados nas rotas do seu prefixo"
        )),
        description = "Retorna quais métodos HTTP são suportados nas rotas do seu prefixo (OK)",
    ), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	))
)]
#[options("")]
async fn user_options(req: HttpRequest) -> impl Responder {
    match jwt_token_middleware(req.headers()) {
        Ok(_) => HttpResponse::Ok()
            .append_header(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
            .finish(),
        Err(e) => e,
    }
}

#[utoipa::path(
    tag = "user",
    path = "/user/{user_id}",
    security(("bearer_auth" = [])),
    responses((
        status = 200, headers((
            "access-control-allow-methods" = Vec<String>, description = "Métodos HTTP suportados nas rotas do seu prefixo"
        )),
        description = "Retorna quais métodos HTTP são suportados nas rotas do seu prefixo (OK)",
    ), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "bearer token": [{
                "code": "unauthorized",
                "message": "Acesso negado por token de autorização.",
                "params": {
                    "min": null,
                    "value": null,
                    "max": null
                }
		    }]
        })
	))
)]
#[options("{user_id}")]
async fn user_id_options(req: HttpRequest) -> impl Responder {
    match jwt_token_middleware(req.headers()) {
        Ok(_) => HttpResponse::Ok()
            .append_header((
                "Access-Control-Allow-Methods",
                "GET, PATCH, PUT, DELETE, OPTIONS",
            ))
            .finish(),
        Err(e) => e,
    }
}
