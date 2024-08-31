use actix_web::HttpResponse;
use std::collections::HashMap;

/// Validate body error.
///
/// Validate body error,differentiating the error between 400 and 422.
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
/// async fn insert_user(
///     body: web::Json<InsertUserDTO>,
///     queue: web::Data<Arc<InsertUserAppQueue>>,
///     redis_pool: web::Data<deadpool_redis::Pool>,
///     postgres_pool: web::Data<deadpool_postgres::Pool>,
/// ) -> impl Responder {
///     match body.validate() {
///         Ok(_) => (),
///         Err(e) => return validate_body_error(e.field_error()),
///     };
///     let redis_user = match Redis::get(&redis_pool, &body.email.clone()).await {
///         Ok(redis_user) => redis_user,
///         Err(_) => String::from(""),
///     };
///     match insert_user_service(queue.clone(), postgres_pool, body, redis_user).await {
///         Ok(resp) => match UserSerdes::serde_json_to_string(&resp) {
///             Ok(redis_user) => {
///                 let _ = Redis::set(&redis_pool, &resp.id, &redis_user).await;
///                 let _ = Redis::set(&redis_pool, &resp.email, &redis_user).await;
///                 HttpResponse::Created()
///                     .append_header(("Location", format!("/user/{}", resp.id)))
///                     .finish()
///             }
///             Err(e) => e,
///         },
///             Err(e) => e,
///     }
/// }
/// ```
pub fn validate_body_error(
    field_errors: HashMap<&'static str, &Vec<validator::ValidationError>>,
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
