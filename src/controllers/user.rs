use crate::{
    config::{queue::AppQueue, redis::Redis},
    dtos::user::CreateUserDTO,
    middlewares::email_exists::email_exists,
    services::user::insert_user_service,
};
use actix_web::{post, web, HttpResponse, Responder};
use serde_json::json;
use std::sync::Arc;
use utoipa;
use validator::Validate;

#[utoipa::path(
    tag = "user",
    request_body = CreateUserDTO,
    responses((
        status = 201, description = "Insere um novo usuário (Created)", headers((
            "location" = String, description = "Link para realizar get de dados do usuário inserido"
        )),
    ), (
        status = 409, description = "Conflito com recurso já no servidor (Conflict)", body = ValidationErrors,
        content_type = "application/json", example = json!({"error": "Este e-mail já está sendo utilizado por outro usuário."})
    ), (
        status = 400, description = "Erro do usuário, por falta de preenchimento de campo ou inválido (Bad Request)",
        body = ValidationErrors, content_type = "application/json", example = json!({"password": [{
            "code": "length",
            "message": "A senha deve ter pelo menos 8 caracteres.",
            "params": {
                "min": 8,
                "value": "string",
                "max": 255
            }
        }]})
    )),
)]
#[post("/user")]
async fn insert_user(
    body: web::Json<CreateUserDTO>,
    queue: web::Data<Arc<AppQueue>>,
    redis_pool: web::Data<deadpool_redis::Pool>,
    pg_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    match body.validate() {
        Ok(_) => {
            match email_exists(&pg_pool, &body).await {
                Ok(_) => (),
                Err(e) => return HttpResponse::Conflict().json(json!({"error": format!("{e}")})),
            };

            let redis_key = format!("a/{}", body.email.clone());
            let _ = Redis::get_redis(&redis_pool, &redis_key).await;

            let id: String = uuid::Uuid::new_v4().to_string();
            match insert_user_service(queue.clone(), body, id.clone()).await {
                Ok(dto) => {
                    let body = serde_json::to_string(&dto).unwrap();
                    let _ = Redis::set_redis(&redis_pool, &id, &body).await;
                    HttpResponse::Created()
                        .append_header(("location", format!("/user/{id}")))
                        .finish()
                }
                Err(e) => HttpResponse::BadRequest().json(e.to_string()),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(e),
    }
}
