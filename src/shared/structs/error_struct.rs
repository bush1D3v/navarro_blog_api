use serde::Serialize;
use utoipa::ToSchema;

#[derive(ToSchema, Serialize)]
pub struct ErrorStruct {
    pub code: String,
    pub message: String,
    pub params: ErrorParams,
}

#[derive(ToSchema, Serialize)]
pub struct ErrorParams {
    pub min: Option<i32>,
    pub value: Option<String>,
    pub max: Option<i32>,
}
