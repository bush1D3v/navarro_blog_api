use crate::shared::{exceptions::exception::Exception, structs::jwt_claims::Claims};
use actix_web::HttpResponse;
use jsonwebtoken::TokenData;
use std::env;

/// # JWT
///
/// ## Purpose
///
/// Treat JWT token models, decode and encode tokens.
///
/// ## Functions
///
/// - `refresh_token_constructor()` - It creates a refresh token
/// - `access_token_constructor()` - It creates a access token
/// - `access_token_decode()` - It decodes an access token
/// - `refresh_token_decode()` - It decodes a refresh token
pub struct Jwt {}

impl Jwt {
    /// # Refresh Token Constructor
    ///
    /// ## Arguments
    ///
    /// * `user_id` - String
    ///
    /// ## Returns
    ///
    /// Refresh token
    ///
    /// ## Errors
    ///
    /// - Internal Server Error - If it fails to create the refresh token
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

    /// # Access Token Constructor
    ///
    /// ## Arguments
    ///
    /// * `user_id` - String
    ///
    /// ## Returns
    ///
    /// Access token
    ///
    /// ## Errors
    ///
    /// - Internal Server Error - If it fails to create the access token
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

    /// # Access Token Decode
    ///
    /// ## Arguments
    ///
    /// * `token` - String
    ///
    /// ## Returns
    ///
    /// Access token data
    ///
    /// ## Errors
    ///
    /// - Unauthorized - If it fails to decode the access token
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

    /// # Refresh Token Decode
    ///
    /// ## Arguments
    ///
    /// * `token` - String
    ///
    /// ## Returns
    ///
    /// Refresh token data
    ///
    /// ## Errors
    ///
    /// - Unauthorized - If it fails to decode the refresh token
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
