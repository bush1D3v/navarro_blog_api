use navarro_blog_api::modules::user::user_dtos::{InsertUserDTO, LoginUserDTO, PutUserDTO};
use serde::{Deserialize, Serialize};

/// Mock User DTO (UserDTO)
///
/// It's used to mock the UserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockUserDTO;
///
/// let user: MockUserDTO = UserModels::complete_user_model();
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct MockUserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

/// Mock Insert User DTO (InsertUserDTO)
///
/// It's used to mock the InsertUserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockInsertUserDTO;
///
/// let user: MockInsertUserDTO = UserModels::simple_user_model();
/// ```
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

/// Mock Login User DTO (LoginUserDTO)
///
/// It's used to mock the LoginUserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockLoginUserDTO;
///
/// let user: MockLoginUserDTO = UserModels::login_user_model();
/// ```
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

/// Mock Detail User DTO (DetailUserDTO)
///
/// It's used to mock the DetailUserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockDetailUserDTO;
///
/// let user: MockDetailUserDTO = UserModels::detail_user_model();
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct MockDetailUserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

/// Mock Delete User DTO (DeleteUserDTO)
///
/// It's used to mock the DeleteUserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockDeleteUserDTO;
///
/// let user: MockDeleteUserDTO = UserModels::delete_user_model();
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct MockDeleteUserDTO {
    pub password: String,
}

/// Mock Put User DTO (PutUserDTO)
///
/// It's used to mock the PutUserDTO struct.
///
/// # Examples
///
/// ```rust
/// use navarro_blog_api::mocks::models::user::UserModels;
/// use navarro_blog_api::mocks::structs::user::MockPutUserDTO;
///
/// let user: MockPutUserDTO = UserModels::put_user_model();
/// ```
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
