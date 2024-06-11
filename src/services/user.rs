use crate::{
    config::queue::AppQueue,
    dtos::user::{CreateUserDTO, UserDTO},
    exceptions::custom_error_to_io_error_kind::{custom_error_to_io_error_kind, CustomError},
    repositories::user::insert_user_repository,
};
use actix_web::web::{Data, Json};
use bcrypt::{hash, DEFAULT_COST};
use std::sync::Arc;

pub async fn insert_user_service(
    queue: Data<Arc<AppQueue>>,
    mut body: Json<CreateUserDTO>,
    id: String,
) -> Result<UserDTO, std::io::Error> {
    let encrypted_password = match hash(&body.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::Bcrypt(&e)),
                e,
            ))
        }
    };
    body.password = encrypted_password;

    Ok(insert_user_repository(queue.clone(), body, id).await)
}
