use crate::{
    modules::user::{
        user_controllers::{
            __path_delete_user, __path_detail_user, __path_insert_user, __path_list_users,
            __path_login_user, __path_put_user, __path_user_id_options, __path_user_options,
        },
        user_dtos::{
            DeleteUserDTO, DetailUserDTO, InsertUserDTO, LoginUserDTO, PutUserDTO, UserDTO,
        },
        user_services::LoginUserServiceResponse,
    },
    shared::structs::{
        error_struct::{ErrorParams, ErrorStruct},
        query_params::QueryParams,
    },
};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

/// # API Documentation
///
/// This function sets up and returns the Swagger UI for the API documentation using the [Utoipa Swagger UI](https://crates.io/crates/utoipa-swagger-ui) and [Utoipa](https://crates.io/crates/utoipa) crate.
///
/// The Swagger UI provides a visual interface for exploring and interacting with the API's endpoints, making it easier for developers to understand and test the API.
///
/// # Purpose
///
/// The purpose of this function is to configure and serve the Swagger UI, which is a web-based interface that allows users to interact with the API's endpoints. It helps in:
/// - Visualizing the API structure
/// - Testing API endpoints
/// - Understanding the request and response formats
///
/// # Usage
///
/// This function is typically called during the setup of the web server to integrate the Swagger UI into the API service. It should be included in the main application configuration.
///
/// # Returns
///
/// This function returns a `SwaggerUi` instance, which is used by the web server to serve the Swagger UI at a specified endpoint.
///
/// # Example
///
/// ```rust
/// use utoipa::{
///     openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
///     Modify, OpenApi,
/// };
/// use utoipa_swagger_ui::SwaggerUi;
///
/// pub fn main() {
///     let swagger_ui = api_doc();
///     // Integrate `swagger_ui` with your web server configuration
/// }
///
/// #[derive(OpenApi)]
/// #[openapi(
///    servers(
///        (
///            url = "https://hub.docker.com/repository/docker/bush1d3v/navarro_blog_api",
///            description = "Docker Image",
///        ),
///        (
///            url = "http://localhost:8080/",
///            description = "Local Server",
///        )
///    ),
///    tags((
///        name = "user", description = "Controladores da entidade de usuário"
///    )),
/// )]
/// pub struct ApiDoc;
///
/// pub fn api_doc() -> SwaggerUi {
///     // Configuration for Swagger UI
///     SwaggerUi::new("/api-docs")
///         .url("/api-docs/openapi.json", ApiDoc::openapi())
/// }
/// ```
///
/// # Dependencies
///
/// Ensure that you have the `utoipa-swagger-ui` crate added to your `Cargo.toml`:
///
/// ```toml
/// [dependencies]
/// utoipa = { version = "4.2.3", features = ["actix_extras"] }
/// utoipa-swagger-ui = { version = "7.1.0", features = ["actix-web"] }
/// ```
///
/// # Notes
///
/// - The Swagger UI will be available at the endpoint specified in the `SwaggerUi::new` method.
/// - Make sure to generate the OpenAPI documentation using `utoipa` or a similar crate and provide the correct URL to the OpenAPI JSON file.
pub fn api_doc() -> SwaggerUi {
    #[derive(OpenApi)]
    #[openapi(
		paths(user_options, insert_user, login_user, detail_user, list_users, delete_user, put_user, user_id_options),
		components(
			schemas(
				InsertUserDTO,
				LoginUserDTO,
                DetailUserDTO,
                DeleteUserDTO,
                PutUserDTO,
                ErrorStruct,
				ErrorParams,
                QueryParams,
                UserDTO,
                LoginUserServiceResponse
			)
		),
		modifiers(& SecurityModifier),
		servers(
            (
                url = "https://hub.docker.com/repository/docker/bush1d3v/navarro_blog_api",
                description = "Docker Image",
		    ),
            (
                url = "http://localhost:8080/",
                description = "Local Server",
		    )
        ),
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
        }
    }

    SwaggerUi::new("{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi())
}
