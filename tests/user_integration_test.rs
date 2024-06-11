pub mod mocks;

#[cfg(test)]
mod tests {
    use crate::mocks::{
        enums::db_table::TablesEnum, functional_tester::FunctionalTester,
        models::user::complete_user_model,
    };
    use actix_web::{
        body,
        dev::ServiceResponse,
        test,
        web::{Bytes, Data},
        App,
    };
    use navarro_blog_api::{
        config::{
            postgres::postgres,
            queue::{db_flush_queue, AppQueue},
            redis::Redis,
        },
        controllers::user::insert_user,
        dtos::user::UserDTO,
    };
    use std::sync::Arc;

    async fn insert_user_before(user: UserDTO, path: &str) -> ServiceResponse {
        let redis_pool = Redis::pool().await;
        let pool = postgres();
        let pool_async = pool.clone();
        let queue = Arc::new(AppQueue::new());
        let queue_async = queue.clone();
        tokio::spawn(async move { db_flush_queue(pool_async, queue_async).await });

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool.clone()))
                .app_data(Data::new(redis_pool.clone()))
                .app_data(Data::new(queue.clone()))
                .service(insert_user),
        )
        .await;

        let req = test::TestRequest::post()
            .uri(path)
            .set_json(user)
            .to_request();

        test::call_service(&app, req).await
    }

    #[actix_web::test]
    async fn _insert_user() {
        let resp = insert_user_before(complete_user_model(), "/user").await;

        assert!(resp.status().is_success());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert_eq!(bytes, Bytes::from_static(b""));

        assert!(FunctionalTester::can_see_in_database(postgres(), TablesEnum::Users, None).await);

        FunctionalTester::delete_from_database(postgres(), TablesEnum::Users).await;
    }

    #[actix_web::test]
    async fn _insert_user_error_name_length() {
        let mut user = complete_user_model();
        user.name = String::from("");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O nome deve ter entre 3 e 63 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_name_regex() {
        let mut user = complete_user_model();
        user.name = String::from("victor -");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O nome deve conter apenas dígitos validos."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_email_length() {
        let mut user = complete_user_model();
        user.email = String::from("");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_email_regex() {
        let mut user = complete_user_model();
        user.email = String::from("navarroTeste@.com");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O e-mail deve ser um endereço válido."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_email_conflict_db() {
        FunctionalTester::insert_in_db_users(postgres(), complete_user_model()).await;
        let resp = insert_user_before(complete_user_model(), "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("Este e-mail já está sendo utilizado por outro usuário"));

        FunctionalTester::delete_from_database(postgres(), TablesEnum::Users).await;

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_password_length() {
        let mut user = complete_user_model();
        user.password = String::from("%");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }

    #[actix_web::test]
    async fn _insert_user_error_password_regex() {
        let mut user = complete_user_model();
        user.password = String::from("12345678");

        let resp = insert_user_before(user, "/user").await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(FunctionalTester::cant_see_in_database(postgres(), TablesEnum::Users, None).await);
    }
}
