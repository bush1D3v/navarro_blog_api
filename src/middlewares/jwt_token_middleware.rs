use crate::{
    shared::{structs::jwt_claims::Claims, treaties::jwt_treated::Jwt},
    utils::error_construct::error_construct,
};
use actix_web::{http::header::HeaderMap, HttpResponse};
use jsonwebtoken::TokenData;

/// Middleware to check if the JWT token is valid.
///
/// # Parameters
///
/// - `headers`: The headers of the request.
///
/// # Returns
///
/// Returns a `Result` which, on success, return the decoded `TokenData`. On failure, returns an `HttpResponse` with the corresponding error.
///
/// # Errors
///
/// This function may return an error if:
///
/// - The authorization header is missing.
/// - The authorization header is malformed.
/// - The authorization header is invalid.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::middlewares::jwt_token_middleware::jwt_token_middleware;
/// use navarro_blog_api::shared::structs::jwt_claims::Claims;
/// use actix_web::{HttpRequest, HttpResponse};
/// use jsonwebtoken::TokenData;
///
/// pub fn example(req: HttpRequest) -> Result<TokenData<Claims>, HttpResponse> {
///     match jwt_token_middleware(req.headers()) {
///         Ok(token) => Ok(token),
///         Err(e) => return Err(e),
///     }
/// }
/// ```
pub fn jwt_token_middleware(headers: &HeaderMap) -> Result<TokenData<Claims>, HttpResponse> {
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

    Jwt::access_token_decode(token)
}
