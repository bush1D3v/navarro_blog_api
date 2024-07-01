use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize)]
pub struct QueryParams {
    pub limit: Option<i8>,
    pub offset: Option<i8>,
    pub order_by: Option<String>,
    pub order_direction: Option<String>,
}
