use actix_web::{web, HttpResponse};

use crate::{
    modules::user::user_repositories::get_user_salt_repository,
    shared::treaties::{
        bcrypt_treated::{Bcrypt, BcryptVerifyData},
        strip_suffix_treated::StripSuffix,
    },
};

/// Verifies the user's password.
///
/// This function checks if the password provided by the user matches the password stored in the database.
///
/// # Parameters
///
/// - `pool`: A connection pool for the database.
/// - `user_id`: The ID of the user whose password is being verified.
/// - `db_user_password`: The password stored in the database for the user.
/// - `input_user_password`: The password provided by the user for verification.
/// - `verifier_context`: The Bcrypt verification context.
///
/// # Returns
///
/// Returns a `Result` which, on success, contains the user's salt. On failure, returns an `HttpResponse` with the corresponding error.
///
/// # Errors
///
/// This function may return an error if:
///
/// - It is not possible to obtain the user's salt from the repository.
/// - The removal of the suffix from the password hash fails.
/// - The password verification fails.
///
/// # Example
///
/// ```rust
/// use navarro_blog_api::utils::password_verifier::password_verifier;
/// use navarro_blog_api::shared::treaties::bcrypt_treated::BcryptVerifyData;
/// use navarro_blog_api::modules::user::user_dtos::{UserDTO, LoginUserDTO};
/// use actix_web::{web::Data, HttpResponse};
/// use deadpool_postgres::Pool;
///
/// pub async fn example(postgres_pool: Data<Pool>, user_id: String, db_user: UserDTO, body: LoginUserDTO) -> Result<String, HttpResponse> {
///     match password_verifier(
///         postgres_pool.clone(),
///         user_id.clone(),
///         db_user.password.clone(),
///         body.password.clone(),
///         BcryptVerifyData::Password(body.password.clone()),
///     ).await {
///         Ok(salt) => Ok(salt),
///         Err(e) => return Err(e),
///     }
/// };
/// ```
pub async fn password_verifier(
    pool: web::Data<deadpool_postgres::Pool>,
    user_id: String,
    db_user_password: String,
    input_user_password: String,
    verifier_context: BcryptVerifyData,
) -> Result<String, HttpResponse> {
    let user_salt = match get_user_salt_repository(user_id.clone(), pool.clone()).await {
        Ok(user_salt) => user_salt,
        Err(e) => return Err(e),
    };
    let hash = match StripSuffix::strip_suffix(db_user_password.clone(), &user_salt) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    match Bcrypt::verify(input_user_password, &hash, verifier_context) {
        Ok(_) => Ok(user_salt),
        Err(e) => Err(e),
    }
}
