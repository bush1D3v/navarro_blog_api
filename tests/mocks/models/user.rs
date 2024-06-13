use navarro_blog_api::modules::user::user_dtos::{CreateUserDTO, UserDTO};

pub fn complete_user_model() -> UserDTO {
    return UserDTO {
        id: uuid::Uuid::new_v4().to_string(),
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
        created_at: chrono::Utc::now().to_string(),
    };
}

pub fn simple_user_model() -> CreateUserDTO {
    return CreateUserDTO {
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
    };
}
