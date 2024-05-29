use crate::controllers::hello_world::{Message, __path_hello_world};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

pub fn api_doc() -> SwaggerUi {
    #[derive(OpenApi)]
    #[openapi(
        paths(hello_world),
        components(schemas(Message)),
        modifiers(&SecurityModifier),
        servers((
            url = "http://localhost:8080",
            description = "Local Server",
        ), (
            url = "https://hub.docker.com/repository/docker/bush1d3v/navarro_blog_api",
            description = "Docker Image",
        )),
    )]
    pub struct ApiDoc;

    struct SecurityModifier;
    impl Modify for SecurityModifier {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components: &mut utoipa::openapi::Components = openapi.components.as_mut().unwrap();
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "basic_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
        }
    }

    return SwaggerUi::new("/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi());
}
