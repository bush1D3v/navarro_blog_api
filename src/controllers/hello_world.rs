use actix_web::{get, HttpResponse, Responder};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

#[derive(OpenApi)]
#[openapi(paths(hello_world), components(schemas(Message)))]
#[derive(Serialize, ToSchema)]
pub struct Message {
    message: String,
}

#[utoipa::path(
    responses((
        status = 200, description = "Route responsible for get a hello world message", body = Message,
        content_type = "application/json", example = json!({"message": "Hello World!"})
    ))
)]
#[get("/world")]
async fn hello_world() -> impl Responder {
    let message: Message = Message {
        message: String::from("Hello World!"),
    };

    HttpResponse::Ok().json(message)
}
