use navarro_blog_api::modules::user::user_dtos::{InsertUserDTO, LoginUserDTO, PutUserDTO};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct MockUserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockInsertUserDTO {
    pub name: String,
    pub email: String,
    pub password: String,
}

impl Into<InsertUserDTO> for MockInsertUserDTO {
    fn into(self) -> InsertUserDTO {
        InsertUserDTO {
            name: self.name,
            email: self.email,
            password: self.password,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockLoginUserDTO {
    pub email: String,
    pub password: String,
}

impl Into<LoginUserDTO> for MockLoginUserDTO {
    fn into(self) -> LoginUserDTO {
        LoginUserDTO {
            email: self.email,
            password: self.password,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockDetailUserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockDeleteUserDTO {
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockPutUserDTO {
    pub password: String,
    pub new_password: String,
    pub email: String,
    pub new_email: String,
}

impl Into<PutUserDTO> for MockPutUserDTO {
    fn into(self) -> PutUserDTO {
        PutUserDTO {
            email: self.email,
            password: self.password,
            new_email: self.new_email,
            new_password: self.new_password,
        }
    }
}
