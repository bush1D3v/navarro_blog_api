use crate::utils::error_construct::error_construct;
use actix_web::HttpResponse;

pub struct Exception;

impl Exception {
    /// Error 400
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
