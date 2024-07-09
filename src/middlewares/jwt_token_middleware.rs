use crate::{shared::treaties::jwt_treated::JWT, utils::error_construct::error_construct};
use actix_web::{http::header::HeaderMap, HttpResponse};

pub fn jwt_token_middleware(headers: &HeaderMap) -> Result<(), HttpResponse> {
    let token = match headers.get("Authorization") {
        Some(header_value) => match header_value.to_str() {
            Ok(header_str) => {
                let token_str = header_str.trim_start_matches("Bearer ");
                token_str.trim()
            }
            Err(e) => {
                return Err(HttpResponse::InternalServerError().json(error_construct(
                    String::from("bearer token"),
                    String::from("internal server error"),
                    e.to_string(),
                    None,
                    None,
                    None,
                )))
            }
        },
        None => {
            return Err(HttpResponse::BadRequest().json(error_construct(
                String::from("bearer token"),
                String::from("bad request"),
                String::from("O valor do cabeçalho 'Authorization' deve ser informado."),
                None,
                None,
                None,
            )))
        }
    };

    match JWT::access_token_decode(token) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
