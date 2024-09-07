use crate::shared::exceptions::exception::Exception;
use actix_web::HttpResponse;

/// # UUID Path Middleware
///
/// This middleware is used to validate and parse the UUID path parameter.
///
/// # Arguments
///
/// * `id` - The UUID path parameter to validate and parse.
/// * `path_name` - The name of the path parameter.
///
/// # Returns
///
/// Returns a `Result<String, HttpResponse>` where:
///
/// * `String` - The parsed UUID path parameter.
/// * `HttpResponse` - An error response with a 422 status code and the provided path name and error message.
///
/// # Example
///
/// ```rust
/// use actix_web::{web, HttpResponse};
/// use uuid::Uuid;
/// use navarro_blog_api::middlewares::uuid_path_middleware::uuid_path_middleware;
///
/// pub async fn get_user_by_id(
///     id: web::Path<String>,
/// ) -> Result<HttpResponse, HttpResponse> {
///     let uuid = uuid_path_middleware(id.to_string(), "id")?;
///     Ok(HttpResponse::Ok().body(uuid))
/// }
/// ```
pub fn uuid_path_middleware(id: String, path_name: &str) -> Result<String, HttpResponse> {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => Ok(uuid.to_string()),
        Err(_) => Err(Exception::unprocessable_entity(
            String::from(path_name),
            String::from("Por favor, envie um valor de UUID válido na URL da requisição."),
            Some(id),
        )),
    }
}
