use crate::utils::error_construct::error_construct;
use actix_web::HttpResponse;

pub struct StripSuffix {}

impl StripSuffix {
    pub fn strip_suffix(input: String, suffix: &str) -> Result<String, HttpResponse> {
        match input.strip_suffix(suffix) {
            Some(input_suffixed) => Ok(input_suffixed.to_string()),
            None => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("server"),
                String::from("internal server error"),
                String::from("Erro ao extrair o salt do usuário."),
                None,
                None,
                None,
            ))),
        }
    }
}
