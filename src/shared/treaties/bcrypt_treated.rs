use actix_web::HttpResponse;
use bcrypt::DEFAULT_COST;

use crate::shared::exceptions::exception::Exception;

/// # Bcrypt
///
/// ## Purpose
///
/// Treat Bcrypt models, hash and verify passwords.
///
/// ## Functions
///
/// - `verify()` - It verifies if the password is correct
/// - `hash()` - It hashes a password
pub struct Bcrypt {}

pub enum BcryptVerifyData {
    EmailPassword(String, String),
    Password(String),
}

impl Bcrypt {
    /// # Verify
    ///
    /// ## Arguments
    ///
    /// * `password` - String
    /// * `hash` - &str
    /// * `data` - BcryptVerifyData
    ///
    /// ## Returns
    ///
    /// Nothing
    ///
    /// ## Errors
    ///
    /// - Unauthorized - If it fails to verify the password/email
    /// - Unauthorized - If it fails to verify the password
    /// - Internal Server Error - If it fails to verify the password
    pub fn verify(
        password: String,
        hash: &str,
        data: BcryptVerifyData,
    ) -> Result<(), HttpResponse> {
        match bcrypt::verify(password, hash) {
            Ok(true) => Ok(()),
            Ok(false) => match data {
                BcryptVerifyData::EmailPassword(email, password) => Err(Exception::unauthorized(
                    String::from("email/password"),
                    String::from("E-mail e/ou senha incorretos."),
                    Some(format!("{}/{}", email, password)),
                )),
                BcryptVerifyData::Password(password) => Err(Exception::unauthorized(
                    String::from("password"),
                    String::from("Senha incorreta."),
                    Some(password),
                )),
            },
            Err(e) => Err(Exception::internal_server_error(
                String::from("bcrypt"),
                e.to_string(),
            )),
        }
    }

    /// # Hash
    ///
    /// ## Arguments
    ///
    /// * `password` - String
    ///
    /// ## Returns
    ///
    /// Hash
    ///
    /// ## Errors
    ///
    /// - Internal Server Error - If it fails to hash the password
    pub fn hash(password: &str) -> Result<String, HttpResponse> {
        match bcrypt::hash(password, DEFAULT_COST - 4) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(Exception::internal_server_error(
                String::from("bcrypt"),
                e.to_string(),
            )),
        }
    }
}
