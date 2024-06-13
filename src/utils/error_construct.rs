use crate::shared::structs::error_struct::{ErrorParams, ErrorStruct};
use serde_json::json;

// Erros do tipo validator::ValidationErros não precisam passar por aqui, pois esta é uma
// função que visa simular um erro deste mesmo tipo, padronizando o retorno de erros e exceções.
pub fn error_construct(
    data: String,
    code: String,
    message: String,
    value: Option<String>,
    min: Option<i32>,
    max: Option<i32>,
) -> serde_json::Value {
    json!({
        data: [ErrorStruct {
                code,
                message,
                params: ErrorParams { min, value, max },
        }]
    })
}
