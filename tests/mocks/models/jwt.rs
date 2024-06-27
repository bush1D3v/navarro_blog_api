use navarro_blog_api::shared::structs::jwt_claims::Claims;

pub fn access_jwt_model(id: String) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &Claims {
            sub: id,
            role: String::from("admin"),
            exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
        },
        &jsonwebtoken::EncodingKey::from_secret(std::env::var("JWT_ACCESS_KEY").unwrap().as_ref()),
    )
    .unwrap()
}

pub fn refresh_jwt_model(id: String) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &Claims {
            sub: id,
            role: String::from("admin"),
            exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
        },
        &jsonwebtoken::EncodingKey::from_secret(std::env::var("JWT_REFRESH_KEY").unwrap().as_ref()),
    )
    .unwrap()
}
