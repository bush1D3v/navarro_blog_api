use actix_web::HttpResponse;
use bcrypt::DEFAULT_COST;

use crate::shared::exceptions::exceptions::Exceptions;

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
                BcryptVerifyData::EmailPassword(email, password) => Err(Exceptions::unauthorized(
                    String::from("email/password"),
                    String::from("E-mail e/ou senha incorretos."),
                    Some(format!("{}/{}", email, password)),
                )),
                BcryptVerifyData::Password(password) => Err(Exceptions::unauthorized(
                    String::from("password"),
                    String::from("Senha incorreta."),
                    Some(password),
                )),
            },
            Err(e) => Err(Exceptions::internal_server_error(
                String::from("bcrypt"),
                e.to_string(),
            )),
        }
    }
    pub fn hash(password: &str) -> Result<String, HttpResponse> {
        match bcrypt::hash(password, DEFAULT_COST - 4) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(Exceptions::internal_server_error(
                String::from("bcrypt"),
                e.to_string(),
            )),
        }
    }
}
