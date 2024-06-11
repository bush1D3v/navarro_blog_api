use crate::{
    config::queue::AppQueue,
    dtos::user::{CreateUserDTO, UserDTO},
};
use actix_web::web::{Data, Json};
use std::sync::Arc;

pub async fn insert_user_repository(
    queue: Data<Arc<AppQueue>>,
    body: Json<CreateUserDTO>,
    id: String,
) -> UserDTO {
    let name = body.name.clone();
    let email = body.email.clone();
    let password = body.password.clone();
    let created_at = chrono::Utc::now().to_string();
    let dto = UserDTO {
        id: id.clone(),
        name,
        email,
        password,
        created_at: created_at.clone(),
    };
    queue.push((id.clone(), body, Some(created_at)));

    dto
}
