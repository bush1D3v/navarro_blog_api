use bcrypt::hash;
use navarro_blog_api::modules::user::user_dtos::{CreateUserDTO, LoginUserDTO, UserDTO};

pub fn complete_user_model() -> UserDTO {
    UserDTO {
        id: uuid::Uuid::new_v4().to_string(),
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
        created_at: chrono::Utc::now().to_string(),
    }
}

pub fn complete_user_model_hashed() -> UserDTO {
    UserDTO {
        id: uuid::Uuid::new_v4().to_string(),
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: hash("12345678%", 4).unwrap().to_string(),
        created_at: chrono::Utc::now().to_string(),
    }
}

pub fn simple_user_model() -> CreateUserDTO {
    CreateUserDTO {
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
    }
}

pub fn simple_user_model_hashed() -> CreateUserDTO {
    CreateUserDTO {
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: hash("12345678%", 4).unwrap().to_string(),
    }
}

pub fn login_user_model() -> LoginUserDTO {
    LoginUserDTO {
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
    }
}
