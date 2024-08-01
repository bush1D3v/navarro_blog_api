pub mod mocks;

#[cfg(test)]
mod unitary_specs {
    use crate::mocks::{
        enums::db_table::TablesEnum,
        functional_tester::FunctionalTester,
        models::{
            postgres::PostgresModels,
            user::{QueryParamsModels, UserModels},
        },
        structs::user::{MockPutUserDTO, MockUserDTO},
    };
    use actix_web::{
        body, test,
        web::{self, Data, Query},
    };
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use navarro_blog_api::{
        modules::user::{
            user_providers::{email_exists, email_not_exists},
            user_queues::{DeleteUserAppQueue, InsertUserAppQueue, PutUserAppQueue},
            user_repositories::{
                delete_user_repository, detail_user_repository, insert_user_repository,
                list_users_repository, login_user_repository, put_user_repository,
            },
            user_services::{
                delete_user_service, detail_user_service, insert_user_service, list_users_service,
                login_user_service, put_user_service,
            },
        },
        shared::structs::jwt_claims::Claims,
    };
    use std::sync::Arc;

    #[test]
    async fn _insert_user_service() {
        dotenv::dotenv().ok();

        let queue = Arc::new(InsertUserAppQueue::new());
        let user = UserModels::simple_user_model();

        let resp = insert_user_service(
            web::Data::new(queue.clone()),
            web::Data::new(PostgresModels::postgres_success()),
            web::Json(user.clone().into()),
            String::from(""),
        )
        .await
        .unwrap();

        let resp_password = resp.password.clone();
        let password_without_salt = resp_password
            .chars()
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .skip(36)
            .rev()
            .collect::<String>();

        assert_eq!(resp.name, user.name);
        assert_eq!(resp.email, user.email);
        assert!(bcrypt::verify(&user.password, &password_without_salt).unwrap());
        assert!(!resp.id.is_empty());
        assert!(!resp.created_at.is_empty());
        assert!(resp.updated_at.is_none());
    }

    #[test]
    async fn _insert_user_service_conflict_error_service_unavailable() {
        dotenv::dotenv().ok();

        let queue = Arc::new(InsertUserAppQueue::new());
        let user = UserModels::simple_user_model();

        FunctionalTester::insert_in_db_users(UserModels::complete_user_model_hashed()).await;

        let resp = insert_user_service(
            web::Data::new(queue.clone()),
            web::Data::new(PostgresModels::postgres_success()),
            web::Json(user.clone().into()),
            String::from(""),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(resp.status(), 409);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("conflict"));
        assert!(bytes.contains("Este e-mail já está sendo utilizado por outro usuário."));
        assert!(bytes.contains(&format!("{}", user.email)));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_service_error_service_unavailable() {
        dotenv::dotenv().ok();

        let queue = Arc::new(InsertUserAppQueue::new());
        let user = UserModels::simple_user_model();

        FunctionalTester::insert_in_db_users(UserModels::complete_user_model_hashed()).await;

        let resp = insert_user_service(
            web::Data::new(queue.clone()),
            web::Data::new(PostgresModels::postgres_error()),
            web::Json(user.clone().into()),
            String::from(""),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_repository() {
        dotenv::dotenv().ok();

        let queue = Arc::new(InsertUserAppQueue::new());

        let user = UserModels::complete_user_model();

        let resp = insert_user_repository(
            web::Data::new(queue.clone()),
            web::Json(UserModels::simple_user_model().into()),
            user.id.clone(),
            uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();

        assert_eq!(resp.id, user.id);
        assert_eq!(resp.name, user.name);
        assert_eq!(resp.email, user.email);
        assert_eq!(resp.password, user.password);
        assert!(resp
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));
        assert!(resp.updated_at.is_none());
    }

    #[test]
    async fn _login_user_service() {
        dotenv::dotenv().ok();

        let mut user = UserModels::complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;

        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let login_user = UserModels::login_user_model();

        let resp = login_user_service(
            login_user.clone().into(),
            web::Data::new(PostgresModels::postgres_success()),
            String::from(""),
        )
        .await
        .unwrap();

        assert_eq!(resp.access_expires_in, 60 * 30);
        assert_eq!(resp.refresh_expires_in, 60 * 60 * 24 * 7);
        let token_data = decode::<Claims>(
            &resp.refresh_token,
            &DecodingKey::from_secret(std::env::var("JWT_REFRESH_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        let token_data = decode::<Claims>(
            &resp.access_token,
            &DecodingKey::from_secret(std::env::var("JWT_ACCESS_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        assert_eq!(resp.user.id, user.id);
        assert_eq!(resp.user.name, user.name);
        assert_eq!(resp.user.email, user.email);
        assert_eq!(resp.user.password, user.password);
        assert_eq!(
            resp.user.created_at.chars().take(10).collect::<String>(),
            user.created_at.chars().take(10).collect::<String>()
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("user_id", &user.id)]))
            .await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_service_error_not_found() {
        dotenv::dotenv().ok();

        let resp = login_user_service(
            UserModels::login_user_model().into(),
            web::Data::new(PostgresModels::postgres_success()),
            String::from(""),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este e-mail."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _login_user_service_error_unauthorized() {
        dotenv::dotenv().ok();

        let mut user = UserModels::complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;

        FunctionalTester::insert_in_db_salt(user.id.clone(), salt).await;

        let mut login_user = UserModels::login_user_model();
        login_user.password = String::from("teste");

        let resp = login_user_service(
            login_user.clone().into(),
            web::Data::new(PostgresModels::postgres_success()),
            String::from(""),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email/password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("E-mail e/ou senha incorretos."));
        assert!(bytes.contains(&login_user.email));
        assert!(bytes.contains(&login_user.password));

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("user_id", &user.id)]))
            .await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_service_error_service_unavailable() {
        dotenv::dotenv().ok();

        let mut user = UserModels::complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;

        FunctionalTester::insert_in_db_salt(user.id.clone(), salt).await;

        let login_user = UserModels::login_user_model();

        let resp = login_user_service(
            login_user.clone().into(),
            web::Data::new(PostgresModels::postgres_error()),
            String::from(""),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("user_id", &user.id)]))
            .await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_repository() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model();

        FunctionalTester::insert_in_db_users(user.clone()).await;

        let resp = login_user_repository(
            user.email.clone(),
            web::Data::new(PostgresModels::postgres_success()),
        )
        .await
        .unwrap();

        assert_eq!(resp.id, user.id);
        assert_eq!(resp.name, user.name);
        assert_eq!(resp.email, user.email);
        assert_eq!(resp.password, user.password);
        assert_eq!(
            resp.created_at.chars().take(10).collect::<String>(),
            user.created_at.chars().take(10).collect::<String>()
        );

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_repository_error_not_found() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model();

        let resp = login_user_repository(
            user.email.clone(),
            web::Data::new(PostgresModels::postgres_success()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este e-mail."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _login_user_repository_error_service_unavailable() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model();

        let resp = login_user_repository(
            user.email.clone(),
            web::Data::new(PostgresModels::postgres_error()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }

    #[test]
    async fn _detail_user_service() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        FunctionalTester::insert_in_db_users(user.clone()).await;

        let resp = detail_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            user.id.clone(),
            String::from(""),
        )
        .await
        .unwrap();

        assert!(resp.id == user.id);
        assert!(resp.name == user.name);
        assert!(resp.email == user.email);
        assert!(resp.password == user.password);
        assert!(resp
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_service_error_not_found() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        let resp = detail_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            user.id.clone(),
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _detail_user_service_error_service_unavailable() {
        dotenv::dotenv().ok();

        let resp = detail_user_service(
            web::Data::new(PostgresModels::postgres_error()),
            UserModels::complete_user_model().id.clone(),
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }

    #[test]
    async fn _detail_user_repository() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        FunctionalTester::insert_in_db_users(user.clone()).await;

        let resp = detail_user_repository(
            web::Data::new(PostgresModels::postgres_success()),
            user.id.clone(),
        )
        .await
        .unwrap();

        assert!(resp.id == user.id);
        assert!(resp.name == user.name);
        assert!(resp.email == user.email);
        assert!(resp.password == user.password);
        assert!(resp
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_repository_error_not_found() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model();

        let resp = detail_user_repository(
            web::Data::new(PostgresModels::postgres_success()),
            user.id.clone(),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _detail_user_repository_error_service_unavailable() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model();

        let resp = detail_user_repository(
            web::Data::new(PostgresModels::postgres_error()),
            user.id.clone(),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }

    #[test]
    async fn _list_users_service() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), total_users);

        users.reverse();
        for i in 0..total_users as usize {
            assert!(resp[i].id == users[i].id);
            assert!(resp[i].name == users[i].name);
            assert!(resp[i].email == users[i].email);
            assert!(resp[i]
                .created_at
                .contains(&users[i].created_at.chars().take(10).collect::<String>()));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_service_offset_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }
        let offset = 2;
        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::offset_query_params_model(offset)),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), total_users - offset as usize);

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users - offset as usize {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in total_users - offset as usize..total_users {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_service_limit_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }
        let limit = 2;
        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::limit_query_params_model(limit)),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), limit as usize);

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in total_users - limit as usize..total_users {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in 0..total_users - limit as usize {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_service_order_by_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::order_by_query_params_model("created_at")),
        )
        .await
        .unwrap();

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(resp[i].created_at > resp[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_service_order_direction_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::order_direction_query_params_model("asc")),
        )
        .await
        .unwrap();

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(resp[i].created_at < resp[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_service_error_service_unavailable() {
        dotenv::dotenv().ok();

        let resp = list_users_service(
            Data::new(PostgresModels::postgres_error()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }

    #[test]
    async fn _list_users_service_error_not_found() {
        dotenv::dotenv().ok();

        let resp = list_users_service(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("users"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foram encontrados usuários."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _list_users_repository() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), total_users);

        users.reverse();
        for i in 0..total_users as usize {
            assert!(resp[i].id == users[i].id);
            assert!(resp[i].name == users[i].name);
            assert!(resp[i].email == users[i].email);
            assert!(resp[i]
                .created_at
                .contains(&users[i].created_at.chars().take(10).collect::<String>()));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_repository_offset_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }
        let offset = 2;
        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::offset_query_params_model(offset)),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), total_users - offset as usize);

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users - offset as usize {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in total_users - offset as usize..total_users {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_repository_limit_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }
        let limit = 2;
        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::limit_query_params_model(limit)),
        )
        .await
        .unwrap();

        assert_eq!(resp.len(), limit as usize);

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in total_users - limit as usize..total_users {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in 0..total_users - limit as usize {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_repository_order_by_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::order_by_query_params_model("created_at")),
        )
        .await
        .unwrap();

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(resp[i].created_at > resp[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_repository_order_direction_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::order_direction_query_params_model("asc")),
        )
        .await
        .unwrap();

        let bytes = serde_json::to_string(&resp).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(resp[i].created_at < resp[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_repository_error_service_unavailable() {
        dotenv::dotenv().ok();

        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_error()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }

    #[test]
    async fn _list_users_repository_error_not_found() {
        dotenv::dotenv().ok();

        let resp = list_users_repository(
            Data::new(PostgresModels::postgres_success()),
            Query(QueryParamsModels::default_query_params_model()),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("users"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foram encontrados usuários."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _delete_user_service() {
        dotenv::dotenv().ok();

        let queue = Arc::new(DeleteUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let email_resp = delete_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            UserModels::complete_user_model().password,
            user.id,
            String::from(""),
        )
        .await
        .unwrap();

        assert_eq!(email_resp, user.email);

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_service_error_not_found() {
        dotenv::dotenv().ok();

        let queue = Arc::new(DeleteUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!(
            "{}{}",
            UserModels::complete_user_model_hashed().password,
            salt
        );

        let resp = delete_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            UserModels::complete_user_model().password,
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));
    }

    #[test]
    async fn _delete_user_service_error_unauthorized() {
        dotenv::dotenv().ok();

        let queue = Arc::new(DeleteUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let error_password = String::from("123456789%");

        let resp = delete_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            error_password.clone(),
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("Senha incorreta."));
        assert!(bytes.contains(&error_password));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_service_error_service_unavailable() {
        dotenv::dotenv().ok();

        let queue = Arc::new(DeleteUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let resp = delete_user_service(
            web::Data::new(PostgresModels::postgres_error()),
            web::Data::new(queue),
            user.password.clone(),
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_repository() {
        dotenv::dotenv().ok();

        let queue = Arc::new(DeleteUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let resp = delete_user_repository(web::Data::new(queue), user.id)
            .await
            .unwrap();

        assert_eq!(resp, ());

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_service() {
        dotenv::dotenv().ok();

        let queue = Arc::new(PutUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password: new_password.clone(),
            new_email: new_email.clone(),
        };

        let resp = put_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            put_user_dto.into(),
            user.id.clone(),
            String::from(""),
        )
        .await
        .unwrap();

        assert_eq!(resp.id, user.id);
        assert_eq!(resp.name, user.name);
        assert_eq!(resp.email, new_email);
        assert_eq!(
            resp.created_at.chars().take(10).collect::<String>(),
            user.created_at.chars().take(10).collect::<String>()
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_service_error_forbidden() {
        dotenv::dotenv().ok();

        let queue = Arc::new(PutUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: String::from("bush1d3v2@gmail.com"),
            new_password,
            new_email: new_email.clone(),
        };

        let resp = put_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            put_user_dto.into(),
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 403);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("forbidden"));
        assert!(bytes.contains("Você não tem permissão para alterar informações associadas a um e-mail que não está vinculado ao seu ID de usuário."));

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_service_error_unauthorized() {
        dotenv::dotenv().ok();

        let queue = Arc::new(PutUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password + "1",
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };

        let resp = put_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            put_user_dto.into(),
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("Senha incorreta."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_service_error_conflict() {
        dotenv::dotenv().ok();

        let queue = Arc::new(PutUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: UserModels::complete_user_model_hashed().email,
        };

        let resp = put_user_service(
            web::Data::new(PostgresModels::postgres_success()),
            web::Data::new(queue),
            put_user_dto.into(),
            user.id,
            String::from(""),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 409);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("conflict"));
        assert!(bytes.contains("Este e-mail já está sendo utilizado por outro usuário"));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_repository() {
        dotenv::dotenv().ok();

        let queue = Arc::new(PutUserAppQueue::new());

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };

        let resp = put_user_repository(
            web::Data::new(queue),
            web::Json(put_user_dto.into()),
            user.id,
        )
        .await
        .unwrap();

        assert!(resp.contains(&user.created_at.chars().take(10).collect::<String>()));

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _email_exists_provider() {
        dotenv::dotenv().ok();

        let user = FunctionalTester::insert_in_db_users(UserModels::complete_user_model()).await;

        let resp = email_exists(
            web::Data::new(PostgresModels::postgres_success()),
            UserModels::simple_user_model().email,
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 409);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("conflict"));
        assert!(bytes.contains("Este e-mail já está sendo utilizado por outro usuário."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _email_exists_provider_error_service_unavailable() {
        dotenv::dotenv().ok();

        let user = FunctionalTester::insert_in_db_users(UserModels::complete_user_model()).await;

        let resp = email_exists(
            web::Data::new(PostgresModels::postgres_error()),
            UserModels::simple_user_model().email,
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _email_not_exists_provider() {
        dotenv::dotenv().ok();

        let user = UserModels::simple_user_model();

        let resp = email_not_exists(
            web::Data::new(PostgresModels::postgres_success()),
            user.email.clone(),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este e-mail."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _email_not_exists_provider_error_service_unavailable() {
        dotenv::dotenv().ok();

        let user = UserModels::simple_user_model();

        let resp = email_not_exists(
            web::Data::new(PostgresModels::postgres_error()),
            user.email.clone(),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));
    }
}

#[cfg(test)]
mod integration_specs {
    use crate::mocks::{
        enums::db_table::TablesEnum,
        functional_tester::FunctionalTester,
        models::{
            jwt::JwtModels,
            postgres::PostgresModels,
            redis::RedisModels,
            user::{QueryParamsModels, UserModels},
        },
        structs::user::{
            MockDeleteUserDTO, MockDetailUserDTO, MockLoginUserDTO, MockPutUserDTO, MockUserDTO,
        },
    };
    use actix_web::{
        body,
        dev::ServiceResponse,
        test,
        web::{Bytes, Data, Query},
        App,
    };
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use navarro_blog_api::{
        modules::user::{
            user_controllers::user_controllers_module,
            user_queues::{
                delete_user_flush_queue, insert_user_flush_queue, put_user_flush_queue,
                DeleteUserAppQueue, InsertUserAppQueue, PutUserAppQueue,
            },
        },
        shared::structs::{jwt_claims::Claims, query_params::QueryParams},
    };
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    pub enum UserTypes {
        InsertUserDTO(MockUserDTO),
        LoginUserDTO(MockLoginUserDTO),
        DetailUserDTO(MockDetailUserDTO, Option<String>),
        ListUsersDTO(Query<QueryParams>, Option<String>),
        DeleteUserDTO(MockDeleteUserDTO, Option<String>, Option<String>),
        PutUserDTO(MockPutUserDTO, Option<String>, Option<String>),
    }

    async fn user_call_http_before(user: UserTypes, pool_error: bool) -> ServiceResponse {
        dotenv::dotenv().ok();
        let redis_pool = RedisModels::pool_success().await;
        let pool;
        if pool_error {
            pool = PostgresModels::postgres_error();
        } else {
            pool = PostgresModels::postgres_success();
        }
        let insert_pool_async = pool.clone();
        let insert_user_queue = Arc::new(InsertUserAppQueue::new());
        let insert_user_queue_async = insert_user_queue.clone();

        let delete_pool_async = pool.clone();
        let delete_user_queue = Arc::new(DeleteUserAppQueue::new());
        let delete_user_queue_async = delete_user_queue.clone();

        let put_pool_async = pool.clone();
        let put_user_queue = Arc::new(PutUserAppQueue::new());
        let put_user_queue_async = put_user_queue.clone();

        tokio::spawn(async move {
            insert_user_flush_queue(insert_pool_async, insert_user_queue_async).await
        });
        tokio::spawn(async move {
            delete_user_flush_queue(delete_pool_async, delete_user_queue_async).await
        });
        tokio::spawn(
            async move { put_user_flush_queue(put_pool_async, put_user_queue_async).await },
        );

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool.clone()))
                .app_data(Data::new(redis_pool.clone()))
                .app_data(Data::new(insert_user_queue.clone()))
                .app_data(Data::new(delete_user_queue.clone()))
                .app_data(Data::new(put_user_queue.clone()))
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
            UserTypes::ListUsersDTO(query_params, jwt) => {
                let order_by = query_params
                    .order_by
                    .clone()
                    .unwrap_or(String::from("created_at"));
                let order_direction = query_params
                    .order_direction
                    .clone()
                    .unwrap_or(String::from("desc"));
                let limit = query_params.limit.unwrap_or(20);
                let offset = query_params.offset.unwrap_or(0);

                let path = format!("/user?limit={limit}&offset={offset}&order_by={order_by}&order_direction={order_direction}");
                let mut request = test::TestRequest::get().uri(&path);

                if let Some(token) = jwt {
                    request = request.append_header(("Authorization", format!("Bearer {}", token)));
                }

                request.to_request()
            }
            UserTypes::DetailUserDTO(user, jwt) => {
                let mut request = test::TestRequest::get().uri(&format!("/user/{}", user.id));

                if let Some(token) = jwt {
                    request = request.append_header(("Authorization", format!("Bearer {}", token)));
                }

                request.to_request()
            }
            UserTypes::DeleteUserDTO(password, user_id, jwt) => {
                let id = user_id.clone().unwrap_or(String::from("123456"));
                let mut request = test::TestRequest::delete()
                    .uri(&format!("/user/{}", id))
                    .set_json(password);

                if let Some(token) = jwt {
                    request = request.append_header(("Authorization", format!("Bearer {}", token)));
                }

                request.to_request()
            }
            UserTypes::PutUserDTO(body, user_id, jwt) => {
                let id = user_id.clone().unwrap_or(String::from("123456"));
                let mut request = test::TestRequest::put()
                    .uri(&format!("/user/{}", id))
                    .set_json(body);

                if let Some(token) = jwt {
                    request = request.append_header(("Authorization", format!("Bearer {}", token)));
                }

                request.to_request()
            }
        };

        test::call_service(&app, req).await
    }

    #[test]
    async fn _insert_user() {
        let user = UserModels::complete_user_model();

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 201);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert_eq!(bytes, Bytes::from_static(b""));

        sleep(Duration::from_secs(2)).await;

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
        let salt = FunctionalTester::get_salt_from_db(None).await;
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("user_id", &salt.user_id)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            TablesEnum::Salt,
            Some(vec![("user_id", &salt.user_id)]),
        )
        .await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_error_name_length() {
        let mut user = UserModels::complete_user_model();
        user.name = String::from("");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O nome deve ter entre 3 e 63 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_name_regex() {
        let mut user = UserModels::complete_user_model();
        user.name = String::from("victor -");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O nome deve conter apenas dígitos validos."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_length() {
        let mut user = UserModels::complete_user_model();
        user.email = String::from("");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_regex() {
        let mut user = UserModels::complete_user_model();
        user.email = String::from("navarroTeste@.com");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ser um endereço válido."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_email_conflict_db() {
        dotenv::dotenv().ok();
        let mut user = UserModels::complete_user_model();
        FunctionalTester::insert_in_db_users(user.clone()).await;

        user.name = String::from("João Navarro");
        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 409);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("conflict"));
        assert!(bytes.contains("Este e-mail já está sendo utilizado por outro usuário"));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("name", &user.name)])
            )
            .await
        );

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _insert_user_error_password_length() {
        let mut user = UserModels::complete_user_model();
        user.password = String::from("%");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_password_regex() {
        let mut user = UserModels::complete_user_model();
        user.password = String::from("12345678");

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _insert_user_error_service_unavailable() {
        dotenv::dotenv().ok();
        let user = UserModels::complete_user_model();

        let resp = user_call_http_before(UserTypes::InsertUserDTO(user.clone()), true).await;

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Salt, "salt", None).await);
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)])
            )
            .await
        );
    }

    #[test]
    async fn _login_user() {
        dotenv::dotenv().ok();

        let mut user = UserModels::complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let resp = user_call_http_before(
            UserTypes::LoginUserDTO(UserModels::login_user_model()),
            false,
        )
        .await;

        assert_eq!(resp.status(), 200);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("access_token"));
        assert!(bytes.contains("refresh_token"));

        let value: Value = serde_json::from_str(&bytes).unwrap();
        let access_token = value["access_token"].as_str().unwrap();
        let refresh_token = value["refresh_token"].as_str().unwrap();

        let token_data = decode::<Claims>(
            &refresh_token,
            &DecodingKey::from_secret(std::env::var("JWT_REFRESH_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        let token_data = decode::<Claims>(
            &access_token,
            &DecodingKey::from_secret(std::env::var("JWT_ACCESS_KEY").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, user.id);

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("user_id", &user.id)]))
            .await;

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_regex() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.email = String::from("teste@gmailcom");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ser um endereço válido."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_length() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.email = String::from("");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_email_not_found() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.email = String::from("teste@gmail.com");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("Não foi encontrado um usuário com este e-mail."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_password_length() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.password = String::from("1234567");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_password_regex() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.password = String::from("12345678");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), false).await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_unauthorized() {
        dotenv::dotenv().ok();

        let mut insert_user = UserModels::complete_user_model_hashed();

        let salt = uuid::Uuid::new_v4().to_string();
        insert_user.password = format!("{}{}", insert_user.password, salt);
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        FunctionalTester::insert_in_db_salt(insert_user.id.clone(), salt.clone()).await;

        let mut login_user = UserModels::login_user_model();
        login_user.password = String::from("1234567%");

        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user.clone()), false).await;

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email/password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("E-mail e/ou senha incorretos."));
        assert!(bytes.contains(&login_user.email));
        assert!(bytes.contains(&login_user.password));

        FunctionalTester::delete_from_database(
            TablesEnum::Salt,
            Some(vec![("user_id", &insert_user.id)]),
        )
        .await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _login_user_error_service_unavailable() {
        dotenv::dotenv().ok();

        let insert_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(insert_user.clone()).await;

        let login_user = UserModels::login_user_model();
        let resp = user_call_http_before(UserTypes::LoginUserDTO(login_user), true).await;

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &insert_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user() {
        dotenv::dotenv().ok();

        let inserted_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(inserted_user.clone()).await;

        let mut detailed_user = UserModels::detail_user_model();
        detailed_user.id = inserted_user.id.clone();
        let jwt = JwtModels::access_jwt_model(inserted_user.id);
        let resp = user_call_http_before(
            UserTypes::DetailUserDTO(detailed_user.clone(), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 200);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains(&detailed_user.id));
        assert!(bytes.contains(&detailed_user.name));
        assert!(bytes.contains(&detailed_user.email));
        assert!(bytes.contains(
            &detailed_user
                .created_at
                .chars()
                .take(10)
                .collect::<String>()
        ));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &detailed_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_error_service_unavailable() {
        dotenv::dotenv().ok();

        let inserted_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(inserted_user.clone()).await;

        let mut detailed_user = UserModels::detail_user_model();
        detailed_user.id = inserted_user.id.clone();
        let jwt = JwtModels::access_jwt_model(inserted_user.id);
        let resp = user_call_http_before(
            UserTypes::DetailUserDTO(detailed_user.clone(), Some(jwt)),
            true,
        )
        .await;
        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &detailed_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_refresh_token_error() {
        dotenv::dotenv().ok();

        let inserted_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(inserted_user.clone()).await;

        let mut detailed_user = UserModels::detail_user_model();
        detailed_user.id = inserted_user.id.clone();

        let resp =
            user_call_http_before(UserTypes::DetailUserDTO(detailed_user.clone(), None), false)
                .await;
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("bearer token"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &detailed_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_jwt_error_unauthorized() {
        dotenv::dotenv().ok();

        let inserted_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(inserted_user.clone()).await;

        let mut detailed_user = UserModels::detail_user_model();
        detailed_user.id = inserted_user.id.clone();

        let resp = user_call_http_before(
            UserTypes::DetailUserDTO(detailed_user.clone(), Some("".to_string())),
            false,
        )
        .await;
        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &detailed_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_error_uuid_path_type_value() {
        dotenv::dotenv().ok();

        let inserted_user = UserModels::complete_user_model_hashed();
        FunctionalTester::insert_in_db_users(inserted_user.clone()).await;

        let mut detailed_user = UserModels::detail_user_model();
        detailed_user.id = "123456".to_string();

        let jwt = JwtModels::access_jwt_model(inserted_user.id);
        let resp = user_call_http_before(
            UserTypes::DetailUserDTO(detailed_user.clone(), Some(jwt)),
            false,
        )
        .await;
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("Por favor, envie um valor de UUID válido na URL da requisição."));
        assert!(bytes.contains("bad request"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &detailed_user.email)]),
        )
        .await;
    }

    #[test]
    async fn _detail_user_not_found_error() {
        dotenv::dotenv().ok();

        let detailed_user = UserModels::detail_user_model();

        let jwt = JwtModels::access_jwt_model(detailed_user.id.clone());
        let resp = user_call_http_before(
            UserTypes::DetailUserDTO(detailed_user.clone(), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _list_users() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let jwt = JwtModels::access_jwt_model(users[0].id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::default_query_params_model()),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 200);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_offset_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let jwt = JwtModels::access_jwt_model(users[0].id.clone());
        let offset = 2;
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::offset_query_params_model(offset)),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 200);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        for i in 0..total_users - offset as usize {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in total_users - offset as usize..total_users {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_limit_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let jwt = JwtModels::access_jwt_model(users[0].id.clone());
        let limit = 2;
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::limit_query_params_model(limit)),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 200);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        for i in total_users - limit as usize..total_users {
            assert!(bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }

        for i in 0..total_users - limit as usize {
            assert!(!bytes.contains(&users[i].email));

            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_order_by_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let jwt = JwtModels::access_jwt_model(users[0].id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::order_by_query_params_model("created_at")),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 200);

        let bytes: String =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        let bytes_serde: Vec<MockDetailUserDTO> = serde_json::from_str(&bytes).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(bytes_serde[i].created_at > bytes_serde[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_order_direction_query_params() {
        dotenv::dotenv().ok();

        let total_users = 5;
        let mut users: Vec<MockUserDTO> = Vec::with_capacity(total_users);

        for i in 0..total_users as usize {
            let mut user = UserModels::complete_user_model_hashed();
            user.email += &i.to_string();

            users.push(FunctionalTester::insert_in_db_users(user).await);
        }

        let jwt = JwtModels::access_jwt_model(users[0].id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::order_direction_query_params_model("asc")),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 200);

        let bytes: String =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        let bytes_serde: Vec<MockDetailUserDTO> = serde_json::from_str(&bytes).unwrap();

        for i in 0..total_users as usize {
            assert!(bytes.contains(&users[i].id));
            assert!(bytes.contains(&users[i].name));
            assert!(bytes.contains(&users[i].email));
            assert!(bytes.contains(&users[i].created_at.chars().take(10).collect::<String>()));
            if i != 4 {
                assert!(bytes_serde[i].created_at < bytes_serde[i + 1].created_at);
            }
            FunctionalTester::delete_from_database(
                TablesEnum::Users,
                Some(vec![("email", &users[i].email)]),
            )
            .await;
        }
    }

    #[test]
    async fn _list_users_error_service_unavailable() {
        dotenv::dotenv().ok();

        let user =
            FunctionalTester::insert_in_db_users(UserModels::complete_user_model_hashed()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::default_query_params_model()),
                Some(jwt),
            ),
            true,
        )
        .await;
        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _list_users_error_not_found() {
        dotenv::dotenv().ok();

        let jwt = JwtModels::access_jwt_model(UserModels::complete_user_model_hashed().id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::default_query_params_model()),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("users"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foram encontrados usuários."));

        assert!(FunctionalTester::cant_see_in_database(TablesEnum::Users, "email", None).await);
    }

    #[test]
    async fn _list_users_error_jwt_unauthorized() {
        dotenv::dotenv().ok();

        let jwt = JwtModels::refresh_jwt_model(UserModels::complete_user_model_hashed().id.clone());
        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(
                Query(QueryParamsModels::default_query_params_model()),
                Some(jwt),
            ),
            false,
        )
        .await;
        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));
    }

    #[test]
    async fn _list_users_error_jwt_authorization_not_found() {
        dotenv::dotenv().ok();

        let resp = user_call_http_before(
            UserTypes::ListUsersDTO(Query(QueryParamsModels::default_query_params_model()), None),
            false,
        )
        .await;
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));
    }

    #[test]
    async fn _delete_user() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let delete_user_dto = MockDeleteUserDTO {
            password: UserModels::complete_user_model().password,
        };
        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 202);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert_eq!(bytes, Bytes::from_static(b""));

        sleep(Duration::from_secs(2)).await;

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );
    }

    #[test]
    async fn _delete_user_error_password_regex() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let delete_user_dto = MockDeleteUserDTO {
            password: String::from("12345678"),
        };
        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_error_password_length() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let delete_user_dto = MockDeleteUserDTO {
            password: String::from("1234567"),
        };
        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_error_jwt_unauthorized() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        let delete_user_dto = MockDeleteUserDTO {
            password: UserModels::complete_user_model().password,
        };

        let jwt = JwtModels::refresh_jwt_model(user.id.clone());

        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;
        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));
    }

    #[test]
    async fn _delete_user_error_jwt_authorization_not_found() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        let delete_user_dto = MockDeleteUserDTO {
            password: UserModels::complete_user_model().password,
        };

        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), None),
            false,
        )
        .await;
        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));
    }

    #[test]
    async fn _delete_user_error_not_found() {
        dotenv::dotenv().ok();

        let user = UserModels::complete_user_model_hashed();

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let delete_user_dto = MockDeleteUserDTO {
            password: UserModels::complete_user_model().password,
        };
        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));
    }

    #[test]
    async fn _delete_user_error_unauthorized() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());

        let error_password = String::from("123456789%");
        let delete_user_dto = MockDeleteUserDTO {
            password: error_password.clone(),
        };

        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("Senha incorreta."));
        assert!(bytes.contains(&error_password));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _delete_user_error_uuid_path_type_value() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let delete_user_dto = MockDeleteUserDTO {
            password: UserModels::complete_user_model().password,
        };
        let resp = user_call_http_before(
            UserTypes::DeleteUserDTO(delete_user_dto, None, Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("Por favor, envie um valor de UUID válido na URL da requisição."));
        assert!(bytes.contains("bad request"));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Salt,
                "salt",
                Some(vec![("salt", &salt)]),
            )
            .await
        );
        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 202);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert_eq!(bytes, Bytes::from_static(b""));

        sleep(Duration::from_secs(2)).await;

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &new_email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_password_length() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: String::from(""),
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_password_regex() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: String::from("12345678"),
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_email_length() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model_hashed().password,
            email: String::from(""),
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_email_regex() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model_hashed().password,
            email: String::from("teste@gmailcom"),
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ser um endereço válido."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_new_password_length() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password: String::from(""),
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 8 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_new_password_regex() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password: String::from("12345678"),
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("A senha deve ter pelo menos 1 caractere especial."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_new_email_length() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2");
        let new_password: String = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model_hashed().password,
            email: String::from(""),
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ter entre 10 e 127 caracteres."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_new_email_regex() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmailcom");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model_hashed().password,
            email: String::from("teste@gmailcom"),
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("O e-mail deve ser um endereço válido."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email)]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_jwt_unauthorized() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::refresh_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("bearer token"));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_jwt_authorization_not_found() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), None),
            false,
        )
        .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("bad request"));
        assert!(bytes.contains("O valor do cabeçalho 'Authorization' deve ser informado."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_not_found() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let user = UserModels::complete_user_model_hashed();

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 404);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("not found"));
        assert!(bytes.contains("Não foi encontrado um usuário com este id."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_unauthorized() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: new_password.clone(),
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 401);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("password"));
        assert!(bytes.contains("unauthorized"));
        assert!(bytes.contains("Senha incorreta."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_forbidden() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: new_password.clone(),
            email: String::from("bush1d3v2@gmail.com"),
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 403);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("user"));
        assert!(bytes.contains("forbidden"));
        assert!(bytes.contains("Você não tem permissão para alterar informações associadas a um e-mail que não está vinculado ao seu ID de usuário."));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_conflict() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = user.email.clone();
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            false,
        )
        .await;

        assert_eq!(resp.status(), 409);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("email"));
        assert!(bytes.contains("conflict"));
        assert!(bytes.contains("Este e-mail já está sendo utilizado por outro usuário"));

        assert!(
            FunctionalTester::can_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &user.email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_uuid_path_type_value() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp =
            user_call_http_before(UserTypes::PutUserDTO(put_user_dto, None, Some(jwt)), false)
                .await;

        assert_eq!(resp.status(), 400);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("Por favor, envie um valor de UUID válido na URL da requisição."));
        assert!(bytes.contains("bad request"));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }

    #[test]
    async fn _put_user_error_service_unavailable() {
        dotenv::dotenv().ok();

        let salt = uuid::Uuid::new_v4().to_string();
        let mut user = UserModels::complete_user_model_hashed();
        user.password = format!("{}{}", user.password, salt);
        FunctionalTester::insert_in_db_users(user.clone()).await;
        FunctionalTester::insert_in_db_salt(user.id.clone(), salt.clone()).await;

        let new_email = String::from("bush1d3v2@gmail.com");
        let new_password = String::from("123456789%");

        let jwt = JwtModels::access_jwt_model(user.id.clone());
        let put_user_dto = MockPutUserDTO {
            password: UserModels::complete_user_model().password,
            email: UserModels::complete_user_model_hashed().email,
            new_password,
            new_email: new_email.clone(),
        };
        let resp = user_call_http_before(
            UserTypes::PutUserDTO(put_user_dto, Some(user.id.clone()), Some(jwt)),
            true,
        )
        .await;

        assert_eq!(resp.status(), 503);

        let bytes =
            String::from_utf8(body::to_bytes(resp.into_body()).await.unwrap().to_vec()).unwrap();

        assert!(bytes.contains("database"));
        assert!(bytes.contains("service unavailable"));

        assert!(
            FunctionalTester::cant_see_in_database(
                TablesEnum::Users,
                "email",
                Some(vec![("email", &new_email.clone())]),
            )
            .await
        );

        FunctionalTester::delete_from_database(TablesEnum::Salt, Some(vec![("salt", &salt)])).await;
        FunctionalTester::delete_from_database(
            TablesEnum::Users,
            Some(vec![("email", &user.email)]),
        )
        .await;
    }
}
