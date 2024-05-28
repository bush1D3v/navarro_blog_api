#[cfg(test)]
mod tests {
    use std::error::Error;

    use actix_web::{
        body::{self, BoxBody},
        dev::ServiceResponse,
        test, web, App,
    };
    use navarro_blog_api::controllers::hello_world::hello_world;

    #[actix_web::test]
    async fn hello_world_test() {
        let app = test::init_service(App::new().service(hello_world)).await;
        let req = test::TestRequest::get().uri("/world").to_request();
        let resp: ServiceResponse = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body: BoxBody = resp.into_body();
        let bytes: Result<web::Bytes, Box<dyn Error>> = body::to_bytes(body).await;

        assert_eq!(
            bytes.unwrap(),
            web::Bytes::from_static(b"{\"message\":\"Hello World!\"}")
        );
    }
}
