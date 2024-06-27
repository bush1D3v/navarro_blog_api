use actix_web::HttpResponse;

use crate::utils::error_construct::error_construct;

pub fn uuid_path_middleware(
    id: actix_web::web::Path<String>,
    path_name: &str,
) -> Result<String, HttpResponse> {
    println!("{}", id);
    let uuid = match id.trim().split('/').last() {
        Some(uuid) => uuid,
        None => {
            return Err(HttpResponse::BadRequest().json(error_construct(
                String::from(path_name),
                String::from("bad request"),
                format!(
                    "Por favor, envie um valor para {} na URL da requisição.",
                    path_name
                ),
                Some(id.to_string()),
                None,
                None,
            )))
        }
    };
    match uuid::Uuid::parse_str(uuid) {
        Ok(uuid) => Ok(uuid.to_string()),
        Err(_) => Err(HttpResponse::BadRequest().json(error_construct(
            String::from(path_name),
            String::from("bad request"),
            String::from("Por favor, envie um valor de UUID válido na URL da requisição."),
            Some(String::from(uuid)),
            None,
            None,
        ))),
    }
}
