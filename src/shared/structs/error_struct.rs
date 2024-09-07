use serde::Serialize;
use utoipa::ToSchema;

/// # Error Struct
///
/// ## Purpose
///
/// Create a default Struct for error return in API.
///
/// ## Fields
///
/// * `code` - Error code
/// * `message` - Error message
/// * `params` - Error parameters
#[derive(ToSchema, Serialize)]
pub struct ErrorStruct {
    pub code: String,
    pub message: String,
    pub params: ErrorParams,
}

/// # Error Params
///
/// ## Fields
///
/// * `min` - Minimum value of error code
/// * `value` - Value of error
/// * `max` - Maximum value of error code
///
/// ## Purpose
///
/// Create a default Struct for error params to return in ErrorStruct params.
#[derive(ToSchema, Serialize)]
pub struct ErrorParams {
    pub min: Option<i32>,
    pub value: Option<String>,
    pub max: Option<i32>,
}
