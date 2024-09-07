use crate::utils::error_construct::error_construct;
use actix_web::HttpResponse;

/// # Exception
///
/// ## Functions:
///
/// bad_request (data: String, message: String) -> HttpResponse Error 400
///
/// unauthorized (data: String, message: String, value: Option<String>) -> HttpResponse Error 401
///
/// forbidden (value: String) -> HttpResponse Error 403
///
/// not_found (data: String, message: String) -> HttpResponse Error 404
///
/// conflict (value: String) -> HttpResponse Error 409
///
/// unprocessable_entity (data: String, message: String, value: Option<String>) -> HttpResponse Error 422
///
/// internal_server_error (data: String, message: String) -> HttpResponse Error 500
///
pub struct Exception;

impl Exception {
    /// Error 400
    ///
    /// ## Arguments
    ///
    /// * `data` - String
    ///
    /// * `message` - String
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 400
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::bad_request(String::from("user"), String::from("bad request"));
    /// ```
    pub fn bad_request(data: String, message: String) -> HttpResponse {
        HttpResponse::BadRequest().json(error_construct(
            data,
            String::from("bad request"),
            message,
            None,
            None,
            None,
        ))
    }

    /// Error 401
    ///
    /// ## Arguments
    ///
    /// * `data` - String
    ///
    /// * `message` - String
    ///
    /// * `value` - Option<String>
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 401
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::unauthorized(String::from("user"), String::from("unauthorized"), None);
    /// ```
    pub fn unauthorized(data: String, message: String, value: Option<String>) -> HttpResponse {
        HttpResponse::Unauthorized().json(error_construct(
            data,
            String::from("unauthorized"),
            message,
            value,
            None,
            None,
        ))
    }

    /// Error 403
    ///
    /// ## Arguments
    ///
    /// * `value` - String
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 403
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::forbidden(String::from("user"));
    /// ```
    pub fn forbidden(value: String) -> HttpResponse {
        HttpResponse::Forbidden().json(error_construct(
                String::from("user"),
                String::from("forbidden"),
                String::from(
                    "Você não tem permissão para alterar informações associadas a um e-mail que não está vinculado ao seu ID de usuário.",
                ),
                Some(value),
                None,
                None,
            ))
    }

    /// Error 404
    ///
    /// ## Arguments
    ///
    /// * `data` - String
    ///
    /// * `message` - String
    ///
    /// * `value` - Option<String>
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 404
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::not_found(String::from("user"), String::from("not found"), None);
    /// ```
    pub fn not_found(data: String, message: String, value: Option<String>) -> HttpResponse {
        HttpResponse::NotFound().json(error_construct(
            data,
            String::from("not found"),
            message,
            value,
            None,
            None,
        ))
    }

    /// Error 409
    ///
    /// ## Arguments
    ///
    /// * `value` - String
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 409
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::conflict(String::from("user"));
    /// ```
    pub fn conflict(value: String) -> HttpResponse {
        HttpResponse::Conflict().json(error_construct(
            String::from("email"),
            String::from("conflict"),
            String::from("Este e-mail já está sendo utilizado por outro usuário."),
            Some(value),
            None,
            None,
        ))
    }

    ///Error 422
    ///
    /// ## Arguments
    ///
    /// * `data` - String
    ///
    /// * `message` - String
    ///
    /// * `value` - Option<String>
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 422
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::unprocessable_entity(String::from("user"), String::from("unprocessable entity"), None);
    /// ```
    pub fn unprocessable_entity(
        data: String,
        message: String,
        value: Option<String>,
    ) -> HttpResponse {
        HttpResponse::UnprocessableEntity().json(error_construct(
            data,
            String::from("unprocessable entity"),
            message,
            value,
            None,
            None,
        ))
    }

    /// Error 500
    ///
    /// ## Arguments
    ///
    /// * `data` - String
    ///
    /// * `message` - String
    ///
    /// ## Returns
    ///
    /// HttpResponse Error 500
    ///
    /// ## Example
    ///
    /// ```rust
    /// use actix_web::HttpResponse;
    /// use navarro_blog_api::shared::exceptions::exception::Exception;
    ///
    /// let response = Exception::internal_server_error(String::from("user"), String::from("internal server error"));
    /// ```
    pub fn internal_server_error(data: String, message: String) -> HttpResponse {
        HttpResponse::InternalServerError().json(error_construct(
            data,
            String::from("internal server error"),
            message,
            None,
            None,
            None,
        ))
    }
}
