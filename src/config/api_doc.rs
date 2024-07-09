use crate::{
    modules::user::{
        user_controllers::{
            DetailUserControllerResponse, ListUserControllerResponse, LoginUserControllerResponse,
            __path_delete_user, __path_detail_user, __path_insert_user, __path_list_users,
            __path_login_user, __path_user_options,
        },
        user_dtos::{CreateUserDTO, DeleteUserDTO, DetailUserDTO, LoginUserDTO},
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

pub fn api_doc() -> SwaggerUi {
    #[derive(OpenApi)]
    #[openapi(
		paths(user_options, insert_user, login_user, detail_user, list_users, delete_user),
		components(
			schemas(
				CreateUserDTO,
				LoginUserDTO,
                DetailUserDTO,
                DeleteUserDTO,
				LoginUserControllerResponse,
                DetailUserControllerResponse,
                ListUserControllerResponse,
                ErrorStruct,
				ErrorParams,
                QueryParams,
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
