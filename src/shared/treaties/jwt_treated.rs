use crate::shared::{exceptions::exception::Exception, structs::jwt_claims::Claims};
use actix_web::HttpResponse;
use jsonwebtoken::TokenData;
use std::env;

pub struct Jwt {}

impl Jwt {
    pub fn refresh_token_constructor(user_id: String) -> Result<String, HttpResponse> {
        let claims = Claims {
            sub: user_id,
            role: String::from("admin"),
            exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
        };

        match jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(env::var("JWT_REFRESH_KEY").unwrap().as_ref()),
        ) {
            Ok(token) => Ok(token),
            Err(e) => Err(Exception::internal_server_error(
                String::from("jsonwebtoken"),
                e.to_string(),
            )),
        }
    }

    pub fn access_token_constructor(user_id: String) -> Result<String, HttpResponse> {
        let claims = Claims {
            sub: user_id,
            role: String::from("admin"),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp() as usize,
        };

        match jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(env::var("JWT_ACCESS_KEY").unwrap().as_ref()),
        ) {
            Ok(token) => Ok(token),
            Err(e) => Err(Exception::internal_server_error(
                String::from("jsonwebtoken"),
                e.to_string(),
            )),
        }
    }

    pub fn access_token_decode(token: &str) -> Result<TokenData<Claims>, HttpResponse> {
        match jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(
                std::env::var("JWT_ACCESS_KEY").unwrap().as_ref(),
            ),
            &jsonwebtoken::Validation::default(),
        ) {
            Ok(token) => Ok(token),
            Err(e) => Err(Exception::unauthorized(
                String::from("bearer token"),
                e.to_string(),
                None,
            )),
        }
    }

    pub fn _refresh_token_decode(token: &str) -> Result<TokenData<Claims>, HttpResponse> {
        match jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(
                std::env::var("JWT_REFRESH_KEY").unwrap().as_ref(),
            ),
            &jsonwebtoken::Validation::default(),
        ) {
            Ok(token) => Ok(token),
            Err(e) => Err(Exception::unauthorized(
                String::from("bearer token"),
                e.to_string(),
                None,
            )),
        }
    }
}
