use super::{
    jwt_token_middleware::jwt_token_middleware, uuid_path_middleware::uuid_path_middleware,
};
use crate::shared::exceptions::exception::Exception;
use actix_web::{HttpRequest, HttpResponse};

/// Auth middleware.
///
/// This function checks if the user is authenticated.
///
/// # Parameters
///
/// - `id`: The ID of the user.
/// - `req`: The request object.
/// - `path_name`: The name of the path.
///
/// # Returns
///
/// Returns a `Result` which, on success, return an empty tuple. On failure, returns an `HttpResponse` with the corresponding error.
///
/// # Errors
///
/// This function may return an error if:
///
/// - The id is not a valid UUID.
/// - The JWT token is empty or invalid.
/// - The JWT token not belongs to the user.
///
///
/// # Example
///
/// ```rust
/// use navarro_blog_api::middlewares::auth_middleware::auth_middleware;
/// use actix_web::{HttpRequest, HttpResponse};
///
/// pub async fn example(id: String, req: HttpRequest, path_name: String) -> Result<(), HttpResponse> {
///     match auth_middleware(id, req, &path_name).await {
///         Ok(_) => Ok(()),
///         Err(e) => return Err(e),
///     }
/// };
/// ```
pub async fn auth_middleware(
    id: String,
    req: HttpRequest,
    path_name: &str,
) -> Result<(), HttpResponse> {
    let id = match uuid_path_middleware(id, path_name) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };
    let token = match jwt_token_middleware(req.headers()) {
        Ok(token) => token,
        Err(e) => return Err(e),
    };

    if token.claims.sub != id {
        return Err(Exception::unauthorized(
            String::from("bearer token"),
            String::from("O token informado não pertence ao usuário."),
            None,
        ));
    }
    Ok(())
}
