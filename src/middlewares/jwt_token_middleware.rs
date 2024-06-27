use crate::{shared::structs::jwt_claims::Claims, utils::error_construct::error_construct};
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

    match jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(std::env::var("JWT_ACCESS_KEY").unwrap().as_ref()),
        &jsonwebtoken::Validation::default(),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(HttpResponse::Unauthorized().json(error_construct(
            String::from("bearer token"),
            String::from("unauthorized"),
            e.to_string(),
            None,
            None,
            None,
        ))),
    }
}
