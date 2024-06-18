pub mod mocks;

#[cfg(test)]
mod unitary_test {
    use crate::mocks::{
        enums::db_table::TablesEnum,
        functional_tester::FunctionalTester,
        models::user::{
            complete_user_model, complete_user_model_hashed, login_user_model, simple_user_model,
        },
    };
    use actix_web::{test, web};
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use navarro_blog_api::{
        infra::postgres::postgres, modules::user::user_queues::CreateUserAppQueue,
        shared::structs::jwt_claims::Claims,
    };
    use std::sync::Arc;

    #[test]
    async fn _insert_user_service() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_services::insert_user_service;

        let queue = Arc::new(CreateUserAppQueue::new());
        let user = complete_user_model();

        let response = insert_user_service(
            web::Data::new(queue.clone()),
            web::Data::new(postgres()),
            web::Json(simple_user_model()),
            user.id.clone(),
        )
        .await
        .unwrap();

        let response_password = response.password.clone();
        let password_without_salt = response_password
            .chars()
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .skip(36)
            .rev()
            .collect::<String>();

        assert_eq!(response.id, user.id);
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
        assert!(bcrypt::verify(&user.password, &password_without_salt).unwrap());
        assert!(response
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));
    }

    #[test]
    async fn _login_user_service() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_services::login_user_service;

        let mut user = complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(postgres(), user.clone()).await;

        FunctionalTester::insert_in_db_salt(postgres(), user.id.clone(), salt).await;

        let login_user = login_user_model();

        let response =
            login_user_service(web::Json(login_user.clone()), web::Data::new(postgres()))
                .await
                .unwrap();

        let token_data = decode::<Claims>(
            &response.refresh_token,
            &DecodingKey::from_secret(std::env::var("JWT_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        let token_data = decode::<Claims>(
            &response.access_token,
            &DecodingKey::from_secret(std::env::var("JWT_KEY2").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Salt,
            Some(vec![("user_id", &user.id)]),
        )
        .await;
        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_repository() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_repositories::insert_user_repository;

        let queue = Arc::new(CreateUserAppQueue::new());

        let user = complete_user_model();

        let response = insert_user_repository(
            web::Data::new(queue.clone()),
            web::Data::new(postgres()),
            web::Json(simple_user_model()),
            user.id.clone(),
            uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();

        assert_eq!(response.id, user.id);
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
        assert_eq!(response.password, user.password);
        assert!(response
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));
    }

    #[test]
    async fn _login_user_repository() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_repositories::login_user_repository;

        let user = complete_user_model();

        FunctionalTester::insert_in_db_users(postgres(), user.clone()).await;

        let response = login_user_repository(user.email.clone(), web::Data::new(postgres()))
            .await
            .unwrap();

        assert_eq!(response.id, user.id);
        assert_eq!(response.password, user.password);

        assert!(
            FunctionalTester::can_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _email_exists_provider() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_providers::email_exists;

        let user = FunctionalTester::insert_in_db_users(postgres(), complete_user_model()).await;

        let pool = web::Data::new(postgres());

        let response = email_exists(pool, simple_user_model().email).await;

        assert!(response.is_err());
        assert_eq!(
            response.err().map(|e| e.to_string()),
            Some(String::from(
                "Este e-mail já está sendo utilizado por outro usuário."
            ))
        );

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _email_not_exists_provider() {
        dotenv::dotenv().ok();
        use navarro_blog_api::modules::user::user_providers::email_not_exists;

        let pool = web::Data::new(postgres());

        let user = simple_user_model();

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;

        let response = email_not_exists(pool, user.email.clone()).await;

        assert!(response.is_err());
        assert_eq!(
            response.err().map(|e| e.to_string()),
            Some(String::from(
                "Não foi encontrado um usuário com este email."
            ))
        );

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::mocks::{
        enums::db_table::TablesEnum,
        functional_tester::FunctionalTester,
        models::{
            postgres::postgres_error,
            user::{complete_user_model, complete_user_model_hashed, login_user_model},
        },
    };
    use actix_web::{
        body,
        dev::ServiceResponse,
        test,
        web::{Bytes, Data},
        App,
    };
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use navarro_blog_api::{
        infra::{postgres::postgres, redis::Redis},
        modules::user::{
            user_controllers::user_controllers_module,
            user_dtos::{LoginUserDTO, UserDTO},
            user_queues::{user_flush_queue, CreateUserAppQueue},
        },
        shared::structs::jwt_claims::Claims,
    };
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    pub enum UserTypes {
        InsertUserDTO(UserDTO),
        LoginUserDTO(LoginUserDTO),
    }

    async fn user_call_http_before(user: UserTypes, pool_error: bool) -> ServiceResponse {
        dotenv::dotenv().ok();
        let redis_pool = Redis::pool().await;
        let pool;
        if pool_error {
            pool = postgres_error();
        } else {
            pool = postgres();
        }
        let pool_async = pool.clone();
        let queue = Arc::new(CreateUserAppQueue::new());
        let queue_async = queue.clone();
        tokio::spawn(async move { user_flush_queue(pool_async, queue_async).await });

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool.clone()))
                .app_data(Data::new(redis_pool.clone()))
                .app_data(Data::new(queue.clone()))
                .service(user_controllers_module()),
        )
        .await;

        let req = match user {
            UserTypes::InsertUserDTO(user) => test::TestRequest::post()
                .uri("/user")
                .set_json(user)
                .to_request(),
            UserTypes::LoginUserDTO(user) => test::TestRequest::post()
                .uri("/user/login")
                .set_json(user)
                .to_request(),
        };

        test::call_service(&app, req).await
    }

    #[test]
    async fn _insert_user() {
        let user = complete_user_model();

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_success());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert_eq!(bytes, Bytes::from_static(b""));

        sleep(Duration::from_secs(2)).await;

        assert!(
            FunctionalTester::can_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Salt,
            Some(vec![("user_id", &user.id)]),
        )
        .await;

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_error_name_length() {
        let mut user = complete_user_model();
        user.name = String::from("");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O nome deve ter entre 3 e 63 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_name_regex() {
        let mut user = complete_user_model();
        user.name = String::from("victor -");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O nome deve conter apenas dígitos validos."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_length() {
        let mut user = complete_user_model();
        user.email = String::from("");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_regex() {
        let mut user = complete_user_model();
        user.email = String::from("navarroTeste@.com");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("O e-mail deve ser um endereço válido."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_conflict_db() {
        dotenv::dotenv().ok();
        let mut user = complete_user_model();
        FunctionalTester::insert_in_db_users(postgres(), user.clone()).await;

        user.name = String::from("João Navarro");
        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("Este e-mail já está sendo utilizado por outro usuário"));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("name", &user.name)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_error_password_length() {
        let mut user = complete_user_model();
        user.password = String::from("%");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_password_regex() {
        let mut user = complete_user_model();
        user.password = String::from("12345678");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert!(resp.status().is_client_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_service_unavailable() {
        dotenv::dotenv().ok();
        let user = complete_user_model();

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), true).await;

        assert!(resp.status().is_server_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("database"));
        assert!(bytes_str.contains("service unavailable"));

        assert!(
            FunctionalTester::cant_see_in_database(
                postgres(),
                TablesEnum::Users,
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _login_user() {
        dotenv::dotenv().ok();

        let mut user = complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(postgres(), user.clone()).await;
        FunctionalTester::insert_in_db_salt(postgres(), user.id.clone(), salt.clone()).await;

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user_model()), false).await;

        assert!(resp.status().is_success());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("access_token"));
        assert!(bytes.contains("refresh_token"));

        let v: Value = serde_json::from_str(&bytes).unwrap();
        let access_token = v["access_token"].as_str().unwrap();
        let refresh_token = v["refresh_token"].as_str().unwrap();

        let token_data = decode::<Claims>(
            &refresh_token,
            &DecodingKey::from_secret(std::env::var("JWT_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        let token_data = decode::<Claims>(
            &access_token,
            &DecodingKey::from_secret(std::env::var("JWT_KEY2").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        FunctionalTester::delete_from_database(postgres(), TablesEnum::Salt, None).await;

        sleep(Duration::from_secs(2)).await;

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_regex() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let mut login_user = login_user_model();
        login_user.email = String::from("teste@gmailcom");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ser um endereço válido."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_length() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let mut login_user = login_user_model();
        login_user.email = String::from("");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_not_found() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let mut login_user = login_user_model();
        login_user.email = String::from("teste@gmail.com");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("Não foi encontrado um usuário com este email."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_password_length() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let mut login_user = login_user_model();
        login_user.password = String::from("1234567");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_password_regex() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let mut login_user = login_user_model();
        login_user.password = String::from("12345678");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_unauthorized() {
        dotenv::dotenv().ok();

        let mut insert_user = complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        insert_user.password = format!("{}{}", insert_user.password, salt);
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        FunctionalTester::insert_in_db_salt(postgres(), insert_user.id.clone(), salt.clone()).await;

        let mut login_user = login_user_model();
        login_user.password = String::from("1234567%");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert!(resp.status().is_client_error());

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("E-mail e/ou senha incorretos."));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Salt,
            Some(vec![("salt", &salt)]),
        )
        .await;
        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_service_unavailable() {
        dotenv::dotenv().ok();

        let insert_user = complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(postgres(), insert_user.clone()).await;

        let login_user = login_user_model();
        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), true).await;

        assert!(resp.status().is_server_error());

        let bytes_str =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes_str.contains("database"));
        assert!(bytes_str.contains("service unavailable"));

        FunctionalTester::delete_from_database(
            postgres(),
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }
}
