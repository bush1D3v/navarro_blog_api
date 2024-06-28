use super::{
    user_dtos::{CreateUserDTO, DetailUserDTO, LoginUserDTO},
    user_queues::CreateUserAppQueue,
    user_serdes::UserSerdes,
    user_services::{detail_user_service, insert_user_service},
};
use crate::{
    infra::redis::Redis,
    middlewares::{
        jwt_token_middleware::jwt_token_middleware, uuid_path_middleware::uuid_path_middleware,
    },
    modules::user::user_services::login_user_service,
    utils::error_construct::error_construct,
};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

pub fn user_controllers_module() -> actix_web::Scope {
    web::scope("/user")
        .service(insert_user)
        .service(login_user)
        .service(detail_user)
}

#[utoipa::path(
	tag = "user",
	request_body = CreateUserDTO,
    path = "user",
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
async fn insert_user(
    body: web::Json<CreateUserDTO>,
    queue: web::Data<Arc<CreateUserAppQueue>>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => {
            match Redis::get_redis(&redis_pool, format!("a/{}", body.email.clone()).as_str()).await
            {
                Ok(_) => HttpResponse::Conflict().json(error_construct(
                    String::from("email"),
                    String::from("conflict"),
                    String::from("Este e-mail já está sendo utilizado por outro usuário."),
                    Some(body.email.clone()),
                    None,
                    None,
                )),
                Err(_) => match insert_user_service(queue.clone(), pg_pool, body).await {
                    Ok(response) => match UserSerdes::serde_json_to_string(&response.user) {
                        Ok(string_user) => {
                            let _ = Redis::set_redis(&redis_pool, &response.user_id, &string_user)
                                .await;
                            HttpResponse::Created()
                                .append_header(("Location", format!("/user/{}", response.user_id)))
                                .finish()
                        }
                        Err(e) => e,
                    },
                    Err(e) => e,
                },
            }
        }
        Err(e) => HttpResponse::BadRequest().json(e),
    }
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct LoginUserControllerResponse {
    pub access_token: String,
    pub access_expires_in: i64,
    pub refresh_token: String,
    pub refresh_expires_in: i64,
}

#[utoipa::path(
	tag = "user",
    path = "user/login",
	request_body = LoginUserDTO,
	responses((
		status = 200, description = "Usuário logado com sucesso (OK)", body = LoginResponse,
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
async fn login_user(
    body: web::Json<LoginUserDTO>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => {
            match Redis::get_redis(&redis_pool, format!("a/{}", body.email.clone()).as_str()).await
            {
                Ok(redis_user) => match UserSerdes::serde_string_to_json(&redis_user) {
                    Ok(user) => {
                        let user = LoginUserDTO {
                            email: user.email,
                            password: user.password,
                        };
                        return match login_user_service(web::Json(user), pg_pool, true).await {
                            Ok(tokens) => HttpResponse::Ok().json(LoginUserControllerResponse {
                                access_token: tokens.access_token,
                                access_expires_in: tokens.access_expires_in,
                                refresh_token: tokens.refresh_token,
                                refresh_expires_in: tokens.refresh_expires_in,
                            }),
                            Err(e) => e,
                        };
                    }
                    Err(e) => return e,
                },
                Err(_) => {
                    return match login_user_service(body, pg_pool, false).await {
                        Ok(tokens) => HttpResponse::Ok().json(LoginUserControllerResponse {
                            access_token: tokens.access_token,
                            access_expires_in: tokens.access_expires_in,
                            refresh_token: tokens.refresh_token,
                            refresh_expires_in: tokens.refresh_expires_in,
                        }),
                        Err(e) => e,
                    }
                }
            }
        }
        Err(e) => return HttpResponse::BadRequest().json(e),
    };
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct DetailUserControllerResponse {
    pub user: DetailUserDTO,
}

#[utoipa::path(
    tag = "user",
    path = "user/{user_id}",
    responses((
        status = 200, description = "Detalhamento de usuário com sucesso (OK)", body = DetailUserControllerResponse,
        content_type = "application/json", example = json ! ({
            "user": {
                "id": "f5d46b1b-6adb-40ac-82d6-b0006cf781c0",
                "name": "borrow lightning",
                "email": "lightning@gmail.com",
                "created_at": "2024-06-18 22:03:54.053147-03",
            }
        })
    ), (
		status = 400, description = "Erro do usuário por id inválido e/ou falta de preenchimento (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({
            "user_id": [{
                "code": "bad request",
                "message": "Por favor, envie um valor de UUID válido na URL da requisição.",
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
async fn detail_user(
    pg_pool: web::Data<deadpool_postgres::Pool>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    match jwt_token_middleware(req.headers()) {
        Ok(_) => (),
        Err(e) => return e,
    };
    let user_id = match uuid_path_middleware(user_id, "user_id") {
        Ok(user_id) => user_id,
        Err(e) => return e,
    };
    return match Redis::get_redis(&redis_pool, &user_id).await {
        Ok(redis_user) => match UserSerdes::serde_string_to_json(&redis_user) {
            Ok(user) => {
                let user = DetailUserDTO {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    created_at: user.created_at,
                };
                HttpResponse::Ok().json(DetailUserControllerResponse { user })
            }
            Err(e) => e,
        },
        Err(_) => match detail_user_service(pg_pool, user_id.clone()).await {
            Ok(pg_user) => match UserSerdes::serde_json_to_string(&pg_user) {
                Ok(redis_user) => {
                    let _ = Redis::set_redis(&redis_pool, &user_id, &redis_user).await;
                    let user = DetailUserDTO {
                        id: pg_user.id,
                        name: pg_user.name,
                        email: pg_user.email,
                        created_at: pg_user.created_at,
                    };
                    HttpResponse::Ok().json(DetailUserControllerResponse { user })
                }
                Err(e) => e,
            },
            Err(e) => e,
        },
    };
}
