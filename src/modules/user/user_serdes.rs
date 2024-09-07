use super::user_dtos::UserDTO;
use crate::shared::exceptions::exception::Exception;
use actix_web::HttpResponse;

pub struct UserSerdes;

impl UserSerdes {
    pub fn serde_json_to_string(user: &UserDTO) -> Result<String, HttpResponse> {
        match serde_json::to_string(user) {
            Ok(x) => Ok(x),
            Err(e) => Err(Exception::internal_server_error(
                String::from("server"),
                e.to_string(),
            )),
        }
    }

    pub fn serde_string_to_json(user: &str) -> Result<UserDTO, HttpResponse> {
        match serde_json::from_str(user) {
            Ok(x) => Ok(x),
            Err(e) => Err(Exception::internal_server_error(
                String::from("server"),
                e.to_string(),
            )),
        }
    }
}
