use crate::shared::exceptions::exception::Exception;
use actix_web::HttpResponse;

pub struct StripSuffix {}

impl StripSuffix {
    pub fn strip_suffix(input: String, suffix: &str) -> Result<String, HttpResponse> {
        match input.strip_suffix(suffix) {
            Some(input_suffixed) => Ok(input_suffixed.to_string()),
            None => Err(Exception::internal_server_error(
                String::from("server"),
                String::from("Erro ao extrair o salt do usuário."),
            )),
        }
    }
}
