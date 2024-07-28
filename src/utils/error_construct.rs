use crate::shared::structs::error_struct::{ErrorParams, ErrorStruct};
use serde_json::json;

/// Construct an default error response.
///
/// This function constructs an error response with the provided `data`, `code`, `message`, `value`, `min`, and `max`.
///
/// # Parameters
///
/// - `data`: The input data that caused the error.
/// - `code`: The text description of status code.
/// - `message`: The message description of the error to be shown to the user.
/// - `value`: The optional value of the input data.
/// - `max`: The optional max length of the input data.
/// - `min`: The optional min length of the input data.
///
/// # Returns
///
/// Returns a `serde_json::Value` with the default error response.
///
/// # Example
///
/// ```rust
/// use navarro_blog_api::utils::error_construct::error_construct;
///
/// let error = error_construct(
///     String::from("email"),
///     String::from("conflict"),
///     String::from("Este e-mail já está sendo utilizado por outro usuário."),
///     Some(String::from("emailDeTeste@gmail.com")),
///     Some(10),
///     Some(127),
/// );
/// ```
pub fn error_construct(
    data: String,
    code: String,
    message: String,
    value: Option<String>,
    min: Option<i32>,
    max: Option<i32>,
) -> serde_json::Value {
    json!({
        data: [ErrorStruct {
                code,
                message,
                params: ErrorParams { min, value, max },
        }]
    })
}
