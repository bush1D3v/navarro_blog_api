use serde::{Deserialize, Serialize};

/// # JWT Claims
///
/// ## Fields
///
/// * `sub` - Subject
/// * `role` - Role
/// * `exp` - Expiration
///
/// ## Purpose
///
/// Create a default Struct for JWT Claims.
#[derive(Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}
