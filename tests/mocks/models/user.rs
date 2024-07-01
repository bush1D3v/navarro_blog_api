use bcrypt::hash;
use navarro_blog_api::{
    modules::user::user_dtos::{CreateUserDTO, DetailUserDTO, LoginUserDTO, UserDTO},
    shared::structs::query_params::QueryParams,
};

pub struct UserModels {}
pub struct QueryParamsModels {}

impl QueryParamsModels {
    pub fn default_query_params_model() -> QueryParams {
        QueryParams {
            limit: Some(20),
            offset: Some(0),
            order_by: Some(String::from("created_at")),
            order_direction: Some(String::from("desc")),
        }
    }

    pub fn limit_query_params_model(limit: i8) -> QueryParams {
        QueryParams {
            limit: Some(limit),
            offset: None,
            order_by: None,
            order_direction: None,
        }
    }

    pub fn offset_query_params_model(offset: i8) -> QueryParams {
        QueryParams {
            limit: None,
            offset: Some(offset),
            order_by: None,
            order_direction: None,
        }
    }

    pub fn order_by_query_params_model(order_by: &str) -> QueryParams {
        QueryParams {
            limit: None,
            offset: None,
            order_by: Some(String::from(order_by)),
            order_direction: None,
        }
    }

    pub fn order_direction_query_params_model(order_direction: &str) -> QueryParams {
        QueryParams {
            limit: None,
            offset: None,
            order_by: None,
            order_direction: Some(String::from(order_direction)),
        }
    }
}

impl UserModels {
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

    pub fn detail_user_model() -> DetailUserDTO {
        DetailUserDTO {
            id: uuid::Uuid::new_v4().to_string(),
            email: String::from("bush1d3v@gmail.com"),
            name: String::from("Victor Navarro"),
            created_at: chrono::Utc::now().to_string(),
        }
    }
}
