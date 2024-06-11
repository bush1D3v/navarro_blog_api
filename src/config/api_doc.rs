use crate::{controllers::user::__path_insert_user, dtos::user::CreateUserDTO};
use serde::{Deserialize, Serialize};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct ValidationErrors {
    password: Vec<ErrorDetail>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct ErrorDetail {
    code: String,
    message: String,
    params: std::collections::HashMap<String, serde_json::Value>,
}

pub fn api_doc() -> SwaggerUi {
    #[derive(OpenApi)]
    #[openapi(
        paths(insert_user),
        components(schemas(CreateUserDTO, ValidationErrors, ErrorDetail)),
        modifiers(&SecurityModifier),
        servers((
            url = "http://localhost:8080",
            description = "Local Server",
        ), (
            url = "https://hub.docker.com/repository/docker/bush1d3v/navarro_blog_api",
            description = "Docker Image",
        )),
        tags((
            name = "user", description = "Controladores da entidade de usuário"
        )),
    )]
    pub struct ApiDoc;

    struct SecurityModifier;
    impl Modify for SecurityModifier {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = match openapi.components.as_mut() {
                Some(components) => components,
                None => unreachable!(),
            };
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

    SwaggerUi::new("/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi())
}
