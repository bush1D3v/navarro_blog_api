use actix_web::HttpResponse;

use crate::utils::error_construct::error_construct;

pub fn uuid_path_middleware(id: String, path_name: &str) -> Result<String, HttpResponse> {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => Ok(uuid.to_string()),
        Err(_) => Err(HttpResponse::BadRequest().json(error_construct(
            String::from(path_name),
            String::from("bad request"),
            String::from("Por favor, envie um valor de UUID válido na URL da requisição."),
            Some(id),
            None,
            None,
        ))),
    }
}
