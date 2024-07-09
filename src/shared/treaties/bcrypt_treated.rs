use actix_web::HttpResponse;
use bcrypt::DEFAULT_COST;

use crate::utils::error_construct::error_construct;

pub struct Bcrypt {}

pub enum BcryptVerifyData {
    EmailPassword(String, String),
    Password(String),
}

impl Bcrypt {
    pub fn verify(
        password: String,
        hash: &str,
        data: BcryptVerifyData,
    ) -> Result<(), HttpResponse> {
        match bcrypt::verify(password, hash) {
            Ok(true) => Ok(()),
            Ok(false) => match data {
                BcryptVerifyData::EmailPassword(email, password) => {
                    Err(HttpResponse::Unauthorized().json(error_construct(
                        String::from("email/password"),
                        String::from("unauthorized"),
                        String::from("E-mail e/ou senha incorretos."),
                        Some(format!("{}/{}", email, password)),
                        None,
                        None,
                    )))
                }
                BcryptVerifyData::Password(password) => {
                    Err(HttpResponse::Unauthorized().json(error_construct(
                        String::from("password"),
                        String::from("unauthorized"),
                        String::from("Senha incorreta."),
                        Some(password),
                        None,
                        None,
                    )))
                }
            },
            Err(e) => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("bcrypt"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        }
    }
    pub fn hash(password: &str) -> Result<String, HttpResponse> {
        match bcrypt::hash(password, DEFAULT_COST - 4) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("bcrypt"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        }
    }
}
