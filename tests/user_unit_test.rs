pub mod mocks;

#[cfg(test)]
mod test {
    use crate::mocks::{
        enums::db_table::TablesEnum,
        functional_tester::FunctionalTester,
        models::user::{complete_user_model, simple_user_model},
    };
    use actix_web::web;
    use navarro_blog_api::config::{postgres::postgres, queue::AppQueue};
    use std::sync::Arc;

    #[actix_rt::test]
    async fn _insert_user_service() {
        use navarro_blog_api::services::user::insert_user_service;

        let queue = Arc::new(AppQueue::new());

        let user = complete_user_model();

        let response = insert_user_service(
            web::Data::new(queue.clone()),
            web::Json(simple_user_model()),
            user.id.clone(),
        )
        .await
        .unwrap();

        assert_eq!(response.id, user.id);
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
        assert!(bcrypt::verify(&user.password, &response.password).unwrap());
        assert!(response
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));
    }

    #[actix_rt::test]
    async fn _insert_user_repository() {
        use navarro_blog_api::repositories::user::insert_user_repository;

        let queue = Arc::new(AppQueue::new());

        let user = complete_user_model();

        let response = insert_user_repository(
            web::Data::new(queue.clone()),
            web::Json(simple_user_model()),
            user.id.clone(),
        )
        .await;

        assert_eq!(response.id, user.id);
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
        assert_eq!(response.password, user.password);
        assert!(response
            .created_at
            .contains(&user.created_at.chars().take(10).collect::<String>()));
    }

    #[actix_rt::test]
    async fn _email_exists_middleware() {
        use navarro_blog_api::middlewares::email_exists::email_exists;

        FunctionalTester::insert_in_db_users(postgres(), complete_user_model()).await;

        let pool = web::Data::new(postgres());
        let simple_user = web::Json(simple_user_model());

        let response = email_exists(&pool, &simple_user).await;

        assert!(response.is_err());
        assert_eq!(
            response.err().map(|e| e.to_string()),
            Some(String::from(
                "Este e-mail já está sendo utilizado por outro usuário."
            ))
        );

        FunctionalTester::delete_from_database(postgres(), TablesEnum::Users).await;
    }
}
