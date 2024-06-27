use crate::utils::error_construct::error_construct;

use super::user_dtos::UserDTO;
use actix_web::HttpResponse;

pub struct UserSerdes;

impl UserSerdes {
    pub fn serde_json_to_string(user: &UserDTO) -> Result<String, HttpResponse> {
        match serde_json::to_string(&user) {
            Ok(x) => Ok(x),
            Err(e) => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("server"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        }
    }

    pub fn serde_string_to_json(user: &str) -> Result<UserDTO, HttpResponse> {
        match serde_json::from_str(&user) {
            Ok(x) => Ok(x),
            Err(e) => Err(HttpResponse::InternalServerError().json(error_construct(
                String::from("server"),
                String::from("internal server error"),
                e.to_string(),
                None,
                None,
                None,
            ))),
        }
    }
}
