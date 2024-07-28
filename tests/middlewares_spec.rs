pub mod mocks;

#[cfg(test)]

mod middlewares_specs {
    use crate::mocks::models::jwt::JwtModels;
    use actix_web::{
        body,
        http::header::{HeaderMap, HeaderName, HeaderValue},
        test,
        web::Path,
    };
    use navarro_blog_api::middlewares::{
        auth_middleware::auth_middleware, jwt_token_middleware::jwt_token_middleware,
        uuid_path_middleware::uuid_path_middleware,
    };

    #[test]
    async fn _jwt_token() {
        dotenv::dotenv().ok();

        let mut header_map_mock: HeaderMap = HeaderMap::new();

        let id = uuid::Uuid::new_v4().to_string();
        let jwt = JwtModels::access_jwt_model(id.clone());

        let authorization_value = format!("Bearer {}", jwt);
        let authorization_header_value = HeaderValue::from_str(&authorization_value).unwrap();
        header_map_mock.insert(
            HeaderName::from_static("authorization"),
            authorization_header_value,
        );

        let token = jwt_token_middleware(&header_map_mock).unwrap();

        assert!(token.claims.sub.contains(&id));
    }

    #[test]
    async fn _jwt_token_error_refresh_token() {
        dotenv::dotenv().ok();

        let mut header_map_mock: HeaderMap = HeaderMap::new();

        let jwt = JwtModels::refresh_jwt_model("123".to_string());

        let authorization_value = format!("Bearer {}", jwt);
        let authorization_header_value = HeaderValue::from_str(&authorization_value).unwrap();
        header_map_mock.insert(
            HeaderName::from_static("authorization"),
            authorization_header_value,
        );

        let resp = jwt_token_middleware(&header_map_mock).err().unwrap();
        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));
    }

    #[test]
    async fn _jwt_token_error_authorization_not_found() {
        dotenv::dotenv().ok();

        let mut header_map_mock: HeaderMap = HeaderMap::new();

        let authorization_value = "Bearer ";
        let authorization_header_value = HeaderValue::from_str(&authorization_value).unwrap();
        header_map_mock.insert(
            HeaderName::from_static("content-type"),
            authorization_header_value,
        );

        let resp = jwt_token_middleware(&header_map_mock).err().unwrap();
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));
    }

    #[test]
    async fn _uuid_path() {
        dotenv::dotenv().ok();

        let uuid = uuid::Uuid::new_v4().to_string();
        let path = Path::from(uuid.clone());
        let resp = uuid_path_middleware(path.clone(), "user_id").unwrap();

        assert_eq!(resp, uuid);
    }

    #[test]
    async fn _uuid_path_error_type_value() {
        dotenv::dotenv().ok();

        let uuid = String::from("Victor");
        let path_value = Path::from(uuid.clone());
        let path_name = "user_id";
        let resp = uuid_path_middleware(path_value.clone(), path_name)
            .err()
            .unwrap();
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains(path_name));
        assert!(bytes.contains("Por favor, envie um valor de UUID válido na URL da requisição."));
        assert!(bytes.contains("bad request"));
    }

    #[test]
    async fn _auth() {
        dotenv::dotenv().ok();

        let id = uuid::Uuid::new_v4().to_string();
        let jwt = JwtModels::access_jwt_model(id.clone());

        let authorization_value = format!("Bearer {}", jwt);

        let request = test::TestRequest::default()
            .append_header(("Authorization", authorization_value))
            .to_http_request();

        let resp = auth_middleware(id, request, "user_id").await.unwrap();

        assert_eq!(resp, ());
    }

    #[test]
    async fn _auth_error_type_value() {
        dotenv::dotenv().ok();

        let id = String::from("Victor");
        let jwt = JwtModels::access_jwt_model(id.clone());
        let authorization_value = format!("Bearer {}", jwt);
        let path_name = "user_id";

        let request = test::TestRequest::default()
            .append_header(("Authorization", authorization_value))
            .to_http_request();

        let resp = auth_middleware(id, request, path_name).await.err().unwrap();

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains(path_name));
        assert!(bytes.contains("Por favor, envie um valor de UUID válido na URL da requisição."));
        assert!(bytes.contains("bad request"));
    }

    #[test]
    async fn _auth_error_refresh_token() {
        dotenv::dotenv().ok();

        let id = uuid::Uuid::new_v4().to_string();
        let jwt = JwtModels::refresh_jwt_model("123".to_string());
        let authorization_value = format!("Bearer {}", jwt);
        let path_name = "user_id";

        let request = test::TestRequest::default()
            .append_header(("Authorization", authorization_value))
            .to_http_request();

        let resp = auth_middleware(id, request, path_name).await.err().unwrap();

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));
    }

    #[test]
    async fn _auth_error_authorization_not_found() {
        dotenv::dotenv().ok();

        let id = uuid::Uuid::new_v4().to_string();
        let authorization_value = "Bearer";
        let path_name = "user_id";

        let request = test::TestRequest::default()
            .append_header(("content-type", authorization_value))
            .to_http_request();

        let resp = auth_middleware(id, request, path_name).await.err().unwrap();

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));
    }
}
