use bcrypt::hash;
use navarro_blog_api::shared::structs::query_params::QueryParams;

use crate::mocks::structs::user::{
    MockDeleteUserDTO, MockDetailUserDTO, MockInsertUserDTO, MockLoginUserDTO, MockPutUserDTO,
    MockUserDTO,
};

/// Models for Query Params
///
/// It contains the Query Params models default and to user entity.
///
/// # Functions
///
/// - `default_query_params_model()` - It creates a default Query Params model.
/// - `limit_query_params_model()` - It creates a Query Params model with limit.
/// - `offset_query_params_model()` - It creates a Query Params model with offset.
/// - `order_by_query_params_model()` - It creates a Query Params model with order_by.
/// - `order_direction_query_params_model()` - It creates a Query Params model with order_direction.
pub struct QueryParamsModels {}

impl QueryParamsModels {
    /// Query Params Default Model
    ///
    /// It creates a default Query Params model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::QueryParamsModels;
    /// use navarro_blog_api::shared::structs::query_params::QueryParams;
    ///
    /// let query_params: QueryParams = QueryParamsModels::default_query_params_model();
    /// ```
    pub fn default_query_params_model() -> QueryParams {
        QueryParams {
            limit: Some(20),
            offset: Some(0),
            order_by: Some(String::from("created_at")),
            order_direction: Some(String::from("desc")),
        }
    }

    /// Query Params Limit Model
    ///
    /// It creates a Query Params model with limit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::QueryParamsModels;
    /// use navarro_blog_api::shared::structs::query_params::QueryParams;
    ///
    /// let limit_query_param: QueryParams = QueryParamsModels::limit_query_params_model(10);
    /// ```
    pub fn limit_query_params_model(limit: i8) -> QueryParams {
        QueryParams {
            limit: Some(limit),
            offset: None,
            order_by: None,
            order_direction: None,
        }
    }

    /// Query Params Offset Model
    ///
    /// It creates a Query Params model with offset.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::QueryParamsModels;
    /// use navarro_blog_api::shared::structs::query_params::QueryParams;
    ///
    /// let offset_query_param: QueryParams = QueryParamsModels::offset_query_params_model(10);
    /// ```
    pub fn offset_query_params_model(offset: i8) -> QueryParams {
        QueryParams {
            limit: None,
            offset: Some(offset),
            order_by: None,
            order_direction: None,
        }
    }

    /// Query Params Order By Model
    ///
    /// It creates a Query Params model with order_by.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::QueryParamsModels;
    /// use navarro_blog_api::shared::structs::query_params::QueryParams;
    ///
    /// let order_by_query_param: QueryParams = QueryParamsModels::order_by_query_params_model("created_at");
    /// ```
    pub fn order_by_query_params_model(order_by: &str) -> QueryParams {
        QueryParams {
            limit: None,
            offset: None,
            order_by: Some(String::from(order_by)),
            order_direction: None,
        }
    }

    /// Query Params Order Direction Model
    ///
    /// It creates a Query Params model with order_direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::QueryParamsModels;
    /// use navarro_blog_api::shared::structs::query_params::QueryParams;
    ///
    /// let order_direction_query_param: QueryParams = QueryParamsModels::order_direction_query_params_model("desc");
    /// ```
    pub fn order_direction_query_params_model(order_direction: &str) -> QueryParams {
        QueryParams {
            limit: None,
            offset: None,
            order_by: None,
            order_direction: Some(String::from(order_direction)),
        }
    }
}

/// Models for Users
///
/// It contains the Mocks UserDTO's models.
///
/// # Functions
///
/// - `complete_user_model()` - It creates a complete user model.
/// - `complete_user_model_hashed()` - It creates a detail user model with hashed password.
/// - `simple_user_model()` - It creates an insert user model.
/// - `simple_user_model_hashed()` - It creates an simple user model with hashed password.
/// - `login_user_model()` - It creates a login user model.
/// - `detail_user_model()` - It creates a detail user model.
pub struct UserModels {}

impl UserModels {
    /// Complete User Model
    ///
    /// It creates a complete user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockUserDTO;
    ///
    /// let user: MockUserDTO = UserModels::complete_user_model();
    /// ```
    pub fn complete_user_model() -> MockUserDTO {
        MockUserDTO {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::from("Victor Navarro"),
            email: String::from("bush1d3v@gmail.com"),
            password: String::from("12345678%"),
            created_at: chrono::Utc::now().to_string(),
            updated_at: None,
        }
    }

    /// Complete User Model Hashed
    ///
    /// It creates a detail user model with hashed password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockUserDTO;
    ///
    /// let user: MockUserDTO = UserModels::complete_user_model_hashed();
    /// ```
    pub fn complete_user_model_hashed() -> MockUserDTO {
        MockUserDTO {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::from("Victor Navarro"),
            email: String::from("bush1d3v@gmail.com"),
            password: hash("12345678%", 4).unwrap().to_string(),
            created_at: chrono::Utc::now().to_string(),
            updated_at: None,
        }
    }

    /// Simple User Model
    ///
    /// It creates an insert user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockInsertUserDTO;
    ///
    /// let user: MockInsertUserDTO = UserModels::simple_user_model();
    /// ```
    pub fn simple_user_model() -> MockInsertUserDTO {
        MockInsertUserDTO {
            name: String::from("Victor Navarro"),
            email: String::from("bush1d3v@gmail.com"),
            password: String::from("12345678%"),
        }
    }

    /// Simple User Model Hashed
    ///
    /// It creates an simple user model with hashed password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockInsertUserDTO;
    ///
    /// let user: MockInsertUserDTO = UserModels::simple_user_model_hashed().into();
    /// ```
    pub fn simple_user_model_hashed() -> MockInsertUserDTO {
        MockInsertUserDTO {
            name: String::from("Victor Navarro"),
            email: String::from("bush1d3v@gmail.com"),
            password: hash("12345678%", 4).unwrap().to_string(),
        }
    }

    /// Login User Model
    ///
    /// It creates a login user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockLoginUserDTO;
    ///
    /// let user: MockLoginUserDTO = UserModels::login_user_model();
    /// ```
    pub fn login_user_model() -> MockLoginUserDTO {
        MockLoginUserDTO {
            email: String::from("bush1d3v@gmail.com"),
            password: String::from("12345678%"),
        }
    }

    /// Detail User Model
    ///
    /// It creates a detail user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockDetailUserDTO;
    ///
    /// let user: MockDetailUserDTO = UserModels::detail_user_model();
    /// ```
    pub fn detail_user_model() -> MockDetailUserDTO {
        MockDetailUserDTO {
            id: uuid::Uuid::new_v4().to_string(),
            email: String::from("bush1d3v@gmail.com"),
            name: String::from("Victor Navarro"),
            created_at: chrono::Utc::now().to_string(),
            updated_at: None,
        }
    }

    /// Delete User Model
    ///
    /// It creates a delete user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockDeleteUserDTO;
    ///
    /// let user: MockDeleteUserDTO = UserModels::delete_user_model();
    /// ```
    pub fn delete_user_model() -> MockDeleteUserDTO {
        MockDeleteUserDTO {
            password: String::from("12345678%"),
        }
    }

    /// Put User Model
    ///
    /// It creates a put user model.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::user::UserModels;
    /// use navarro_blog_api::tests::mocks::structs::user::MockPutUserDTO;
    ///
    /// let user: MockPutUserDTO = UserModels::put_user_model();
    /// ```
    pub fn put_user_model() -> MockPutUserDTO {
        MockPutUserDTO {
            email: String::from("bush1d3v@gmail.com"),
            password: String::from("12345678%"),
            new_email: String::from("bush1d3v2@gmail.com"),
            new_password: String::from("123456789%"),
        }
    }
}
