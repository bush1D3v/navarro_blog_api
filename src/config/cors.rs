use actix_cors::Cors;
use actix_web::http;
use std::env;

/// # CORS Configuration
///
/// This function sets up and returns a CORS (Cross-Origin Resource Sharing) configuration using the `actix-cors` crate.
///
/// CORS is a security feature implemented by web browsers to prevent web pages from making requests to a different domain than the one that served the web page. This function configures the CORS settings to allow or restrict cross-origin requests to your API.
///
/// # Purpose
///
/// The purpose of this function is to configure the CORS settings for the Actix web server. It allows the server to specify which origins, methods, and headers are permitted in cross-origin requests. This is essential for enabling secure interactions between the frontend and backend of a web application.
///
/// # Usage
///
/// This function is typically called during the setup of the Actix web server to integrate the CORS middleware into the application. It should be included in the main application configuration.
///
/// # Returns
///
/// This function returns a `Cors` instance, which is used by the Actix web server to enforce the specified CORS policy.
///
/// # Example
///
/// ```rust
/// use actix_cors::Cors;
/// use actix_web::{web, http, App, HttpServer};
/// use std::env;
///
/// async fn server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     HttpServer::new(|| {
///         App::new()
///             .wrap(cors())
///             // Add other routes and middleware here
///     })
///     .bind("127.0.0.1:8080")
///     .expect("Can not bind to port 8080")
///     .run()
///     .await?;
///
///     Ok(())
/// }
///
/// pub fn cors() -> Cors {
///     Cors::default()
///         .allowed_origin(&format!(
///             "{}:{}",
///             env::var("BASE_URL").unwrap(),
///             env::var("HTTP_PORT").unwrap()
///         ))
///         .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"])
///         .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
///         .allowed_header(http::header::CONTENT_TYPE)
///         .max_age(3600)
/// }
/// ```
///
/// # Environment Variables
///
/// - `BASE_URL`: The base URL of your application (e.g., `http://localhost`).
/// - `HTTP_PORT`: The port on which your application is running (e.g., `8080`).
///
/// # Notes
///
/// - The `allowed_origin` method sets the allowed origin for cross-origin requests. It uses the `BASE_URL` and `HTTP_PORT` environment variables to construct the allowed origin.
/// - The `allowed_methods` method specifies the HTTP methods that are allowed for cross-origin requests.
/// - The `allowed_headers` and `allowed_header` methods specify the HTTP headers that are allowed in cross-origin requests.
/// - The `max_age` method sets the maximum age (in seconds) for the CORS preflight request to be cached by the browser.
pub fn cors() -> Cors {
    Cors::default()
        .allowed_origin(&format!(
            "{}:{}",
            env::var("BASE_URL").unwrap(),
            env::var("HTTP_PORT").unwrap()
        ))
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600)
}
