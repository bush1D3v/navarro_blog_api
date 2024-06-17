use super::{
    user_dtos::{CreateUserDTO, LoginUserDTO},
    user_providers::{email_exists, email_not_exists},
    user_queues::CreateUserAppQueue,
    user_services::insert_user_service,
};
use crate::{
    infra::redis::Redis, modules::user::user_services::login_user_service,
    utils::error_construct::error_construct,
};
use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::{io::ErrorKind, sync::Arc};
use utoipa::ToSchema;
use validator::Validate;

pub fn user_controllers_module() -> actix_web::Scope {
    web::scope("/user").service(insert_user).service(login_user)
}

#[utoipa::path(
	tag = "user",
	request_body = CreateUserDTO,
	responses((
		status = 201, description = "Insere um novo usuário (Created)", headers((
			"location" = String, description = "Link para realizar get de dados do usuário inserido"
		)),
	), (
		status = 400, description = "Erro do usuário, por falta de preenchimento de campo ou inválido (Bad Request)",
		body = ValidationErrors, content_type = "application/json", example = json ! ({"password": [{
			"code": "length",
			"message": "A senha deve ter pelo menos 8 caracteres.",
			"params": {
				"min": 8,
				"value": "senha12",
				"max": 255
			}
		}]})
	), (
		status = 409, description = "Conflito com recurso já no servidor (Conflict)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"email": [{
			"code": "conflict",
			"message": "Este e-mail já está sendo utilizado por outro usuário.",
			"params": {
				"min": null,
				"value": "teste@gmail.com",
				"max": null,
			}
		}]})
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"bcrypt": [{
			"code": "internal server error",
			"message": "bcrypt: hash creation failed",
			"params": {
				"min": null,
				"value": null,
				"max": null,
			}
		}]})
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"database": [{
			"code": "service unavailable",
			"message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
			"params": {
				"min": null,
				"value": null,
				"max": null,
			}
		}]})
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
            match email_exists(pg_pool.clone(), body.email.clone()).await {
                Ok(_) => (),
                Err(e) => match e.kind() {
                    ErrorKind::InvalidInput => {
                        return HttpResponse::Conflict().json(error_construct(
                            String::from("email"),
                            String::from("conflict"),
                            e.to_string(),
                            Some(body.email.clone()),
                            None,
                            None,
                        ));
                    }
                    ErrorKind::ConnectionAborted => {
                        return HttpResponse::ServiceUnavailable().json(error_construct(
                            String::from("database"),
                            String::from("service unavailable"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                    _ => {
                        return HttpResponse::InternalServerError().json(error_construct(
                            String::from("server"),
                            String::from("internal server error"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                },
            };

            let redis_key = format!("a/{}", body.email.clone());
            let _ = Redis::get_redis(&redis_pool, &redis_key).await;

            let id = uuid::Uuid::new_v4().to_string();
            match insert_user_service(queue.clone(), pg_pool, body, id.clone()).await {
                Ok(dto) => {
                    match serde_json::to_string(&dto) {
                        Ok(string_dto) => {
                            let _ = Redis::set_redis(&redis_pool, &id, &string_dto).await;
                            return HttpResponse::Created()
                                .append_header(("location", format!("/user/{id}")))
                                .finish();
                        }
                        Err(e) => {
                            return HttpResponse::InternalServerError().json(error_construct(
                                String::from("server"),
                                String::from("internal server error"),
                                e.to_string(),
                                None,
                                None,
                                None,
                            ));
                        }
                    };
                }
                Err(e) => match e.kind() {
                    ErrorKind::InvalidInput => {
                        return HttpResponse::InternalServerError().json(error_construct(
                            String::from("bcrypt"),
                            String::from("internal server error"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                    ErrorKind::ConnectionAborted => {
                        return HttpResponse::ServiceUnavailable().json(error_construct(
                            String::from("database"),
                            String::from("service unavailable"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                    _ => {
                        return HttpResponse::InternalServerError().json(error_construct(
                            String::from("server"),
                            String::from("internal server error"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                },
            }
        }
        Err(e) => HttpResponse::BadRequest().json(e),
    }
}

#[derive(ToSchema, Serialize, Deserialize)]
pub struct LoginUserControllerResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[utoipa::path(
	tag = "user",
	request_body = LoginUserDTO,
	responses((
		status = 200, description = "Usuário logado com sucesso (OK)", body = LoginResponse,
		content_type = "application/json", example = json ! ({
			"access_token": "string",
			"refresh_token": "string"
		})
	), (
		status = 400, description = "Erro do usuário por campo inválido e/ou falta de preenchimento (Bad Request)",
		body = ErrorStruct, content_type = "application/json", example = json ! ({"password": [{
			"code": "length",
			"message": "A senha deve ter pelo menos 8 caracteres.",
			"params": {
				"min": 8,
				"value": "senha",
				"max": 255
			}
		}]})
	), (
		status = 401, description = "Credenciais de autenticação inválidas (Unauthorized)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"password": [{
			"code": "unauthorized",
			"message": "E-mail e/ou senha incorretos.",
			"params": {
				"min": null,
				"value": "Senha123",
				"max": null
			}
		}]})
	), (
		status = 404, description = "Usuário não encontrado (Not Found)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"email": [{
			"code": "not found",
			"message": "Não foi encontrado um usuário com este email.",
			"params": {
				"min": null,
				"value": "teste@gmail.com",
				"max": null
			}
		}]})
	), (
		status = 500, description = "Erro Interno do Servidor (Internal Server Error)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"bcrypt": [{
			"code": "internal server error",
			"message": "bcrypt: hash creation failed",
			"params": {
				"min": null,
				"value": null,
				"max": null,
			}
		}]})
	), (
		status = 503, description = "Serviço Indisponível (Service Unavailable)", body = ErrorStruct,
		content_type = "application/json", example = json ! ({"database": [{
			"code": "service unavailable",
			"message": "Error occurred while creating a new object: db error: FATAL: password authentication failed for user \"postgres\"",
			"params": {
				"min": null,
				"value": null,
				"max": null,
			}
		}]})
	))
)]
#[post("login")]
async fn login_user(
    body: web::Json<LoginUserDTO>,
    pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => match email_not_exists(pool.clone(), body.email.clone()).await {
            Err(e) => match e.kind() {
                ErrorKind::NotFound => HttpResponse::NotFound().json(error_construct(
                    String::from("email"),
                    String::from("not found"),
                    e.to_string(),
                    Some(body.email.clone()),
                    None,
                    None,
                )),
                ErrorKind::ConnectionAborted => {
                    return HttpResponse::ServiceUnavailable().json(error_construct(
                        String::from("database"),
                        String::from("service unavailable"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    ));
                }
                _ => {
                    return HttpResponse::InternalServerError().json(error_construct(
                        String::from("server"),
                        String::from("internal server error"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    ));
                }
            },
            Ok(_) => match login_user_service(body, pool).await {
                Ok(tokens) => HttpResponse::Ok().json(LoginUserControllerResponse {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                }),
                Err(e) => match e.kind() {
                    ErrorKind::InvalidData => HttpResponse::Unauthorized().json(error_construct(
                        String::from("email/password"),
                        String::from("unauthorized"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    )),
                    ErrorKind::InvalidInput => {
                        HttpResponse::InternalServerError().json(error_construct(
                            String::from("bcrypt"),
                            String::from("internal server error"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ))
                    }
                    ErrorKind::Other => HttpResponse::InternalServerError().json(error_construct(
                        String::from("jsonwebtoken"),
                        String::from("internal server error"),
                        e.to_string(),
                        None,
                        None,
                        None,
                    )),
                    ErrorKind::ConnectionAborted => {
                        return HttpResponse::ServiceUnavailable().json(error_construct(
                            String::from("database"),
                            String::from("service unavailable"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                    _ => {
                        return HttpResponse::InternalServerError().json(error_construct(
                            String::from("server"),
                            String::from("internal server error"),
                            e.to_string(),
                            None,
                            None,
                            None,
                        ));
                    }
                },
            },
        },
        Err(e) => HttpResponse::BadRequest().json(e),
    }
}
