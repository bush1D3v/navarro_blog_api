use crate::shared::exceptions::exception::Exception;
use actix_web::HttpResponse;

/// # Strip Suffix
///
/// ## Purpose
///
/// Strip suffix the salt from a user_password
///
/// ## Arguments
///
/// * `input` - String
/// * `suffix` - String
///
/// ## Returns
///
/// String
///
/// ## Errors
///
/// - Internal Server Error - If it fails to strip the suffix
///
/// ## Example
///
/// ```rust
/// use actix_web::HttpResponse;
/// use navarro_blog_api::shared::treaties::strip_suffix_treated::StripSuffix;
///
/// let password = String::from("test12856464656454545");
/// let salt = "12856464656454545";
///
/// let response = StripSuffix::strip_suffix(password, salt);
/// ```
pub struct StripSuffix {}

impl StripSuffix {
    pub fn strip_suffix(input: String, suffix: &str) -> Result<String, HttpResponse> {
        match input.strip_suffix(suffix) {
            Some(input_suffixed) => Ok(input_suffixed.to_string()),
            None => Err(Exception::internal_server_error(
                String::from("server"),
                String::from("Erro ao extrair o salt do usuário."),
            )),
        }
    }
}
