use crate::shared::exceptions::exceptions::Exceptions;
use actix_web::HttpResponse;

pub fn uuid_path_middleware(id: String, path_name: &str) -> Result<String, HttpResponse> {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => Ok(uuid.to_string()),
        Err(_) => Err(Exceptions::unprocessable_entity(
            String::from(path_name),
            String::from("Por favor, envie um valor de UUID válido na URL da requisição."),
            Some(id),
        )),
    }
}
