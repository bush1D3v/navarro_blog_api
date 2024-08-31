use actix_web::HttpResponse;
use std::collections::HashMap;
use validator::ValidationError;

/// Validate body error.
///
/// Validate body error, differentiating the error between 400 and 422.
///
/// # Parameters
///
/// - `field_errors`: Field errors from the validator.
///
/// # Returns
///
/// Returns a `HttpResponse` with the validation errors.
///
/// # Example
///
/// ```rust
/// use navarro_blog_api::modules::user::user_dtos::InsertUserDTO;
/// use navarro_blog_api::utils::validate_body_error::validate_body_error;
/// use actix_web::{web, HttpResponse, Responder};
/// use validator::Validate;
///
/// async fn insert_user(
///     body: web::Json<InsertUserDTO>,
/// ) -> impl Responder {
///     match body.validate() {
///         Ok(_) => HttpResponse::Created().json(body),
///         Err(e) => validate_body_error(e.field_errors()),
///     }
/// }
/// ```
pub fn validate_body_error(
    field_errors: HashMap<&'static str, &Vec<ValidationError>>,
) -> HttpResponse {
    let mut errors = Vec::new();

    for (_field, field_errors) in field_errors {
        for error in field_errors {
            errors.push(error.clone());
        }
    }

    if errors.iter().any(|e| e.code == "regex") {
        HttpResponse::UnprocessableEntity().json(errors)
    } else {
        HttpResponse::BadRequest().json(errors)
    }
}
