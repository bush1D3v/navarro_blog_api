use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// # Query Params
///
/// ## Fields
///
/// * `limit` - Limit of query
/// * `offset` - Offset of query
/// * `order_by` - Order by
/// * `order_direction` - Order direction
///
/// ## Purpose
///
/// Create a default Struct for query params.
#[derive(ToSchema, Serialize, Deserialize)]
pub struct QueryParams {
    pub limit: Option<i8>,
    pub offset: Option<i8>,
    pub order_by: Option<String>,
    pub order_direction: Option<String>,
}
