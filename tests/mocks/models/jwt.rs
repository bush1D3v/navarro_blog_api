use navarro_blog_api::shared::structs::jwt_claims::Claims;

/// Models for JWT
///
/// It contains the JWT token models.
///
/// # Functions
///
/// - `access_jwt_model()` - It creates an access JWT token.
/// - `refresh_jwt_model()` - It creates an refresh JWT token.
pub struct JwtModels {}

impl JwtModels {
    /// Access JWT model
    ///
    /// It creates an access JWT token.
    ///
    /// # Parameters
    ///
    /// * `id` - String
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to guarantee a authenticated connection if used in header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::jwt::JwtModels;
    ///
    /// let user_id = uuid::Uuid::new_v4().to_string();
    /// let jwt = JwtModels::access_jwt_model(id: user_id);
    /// ```
    pub fn access_jwt_model(id: String) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &Claims {
                sub: id,
                role: String::from("admin"),
                exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
            },
            &jsonwebtoken::EncodingKey::from_secret(
                std::env::var("JWT_ACCESS_KEY").unwrap().as_ref(),
            ),
        )
        .unwrap()
    }

    /// Refresh JWT model
    ///
    /// It creates an refresh JWT token.
    ///
    /// # Parameters
    ///
    /// * `id` - String
    ///
    /// # Recommended Use
    ///
    /// In tests, these model is used to throw a refresh token error if used in header.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use navarro_blog_api::mocks::models::jwt::JwtModels;
    ///
    /// let user_id = uuid::Uuid::new_v4().to_string();
    /// let jwt = JwtModels::refresh_jwt_model(id: user_id);
    /// ```
    pub fn refresh_jwt_model(id: String) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &Claims {
                sub: id,
                role: String::from("admin"),
                exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
            },
            &jsonwebtoken::EncodingKey::from_secret(
                std::env::var("JWT_REFRESH_KEY").unwrap().as_ref(),
            ),
        )
        .unwrap()
    }
}
