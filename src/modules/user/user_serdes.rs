use super::user_dtos::UserDTO;
use crate::shared::exceptions::exception::Exception;
use actix_web::HttpResponse;

/// # User Serdes Module
///
/// This module contains all the serdes for the user endpoints.
///
/// ## Usage
///
/// This module is used to define the serdes for the user endpoints.
///
/// ## Returns
///
/// This function returns a `UserSerdes` instance, which is used by the web server to serialize and deserialize the user DTO.
pub struct UserSerdes;

impl UserSerdes {
    /// Serialize User DTO
    ///
    /// This function serializes the user DTO to a string.
    ///
    /// # Parameters
    ///
    /// - `user`: The user DTO to be serialized.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which, on success, contains the serialized user DTO. On failure, returns an `HttpResponse` with the corresponding error.
    pub fn serde_json_to_string(user: &UserDTO) -> Result<String, HttpResponse> {
        match serde_json::to_string(user) {
            Ok(x) => Ok(x),
            Err(e) => Err(Exception::internal_server_error(
                String::from("server"),
                e.to_string(),
            )),
        }
    }

    /// Deserialize User DTO
    ///
    /// This function deserializes the user DTO from a string.
    ///
    /// # Parameters
    ///
    /// - `user`: The user DTO to be deserialized.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which, on success, contains the deserialized user DTO. On failure, returns an `HttpResponse` with the corresponding error.
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
