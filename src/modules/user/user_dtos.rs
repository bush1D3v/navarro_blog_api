use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub created_at: String,
}

static RE_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(^[a-zA-ZÀ-ÿ0-9\s]+$)|(^.*?[@$!%*?&].*$)").unwrap());
static RE_PASSWORD: Lazy<Regex> = Lazy::new(|| Regex::new("^.*?[@$!%*?&].*$").unwrap());
static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

#[derive(Serialize, Deserialize, ToSchema, Validate, Clone)]
pub struct CreateUserDTO {
    #[validate(
		length(
			min = 3,
			max = 63,
			message = "O nome deve ter entre 3 e 63 caracteres."
		),
		regex(
			path = * RE_NAME,
			message = "O nome deve conter apenas dígitos validos."
		)
	)]
    #[serde(default)]
    pub name: String,

    #[validate(
		email(message = "O e-mail deve ser um endereço válido."),
		length(
			min = 10,
			max = 127,
			message = "O e-mail deve ter entre 10 e 127 caracteres."
		),
		regex(path = * RE_EMAIL, message = "O e-mail deve ser um endereço válido.")
	)]
    #[serde(default)]
    pub email: String,

    #[validate(
		length(
			min = 8,
			max = 255,
			message = "A senha deve ter pelo menos 8 caracteres."
		),
		regex(
			path = * RE_PASSWORD,
			message = "A senha deve ter pelo menos 1 caractere especial."
		)
	)]
    #[serde(default)]
    pub password: String,
}

#[derive(Serialize, Deserialize, ToSchema, Validate, Clone)]
pub struct LoginUserDTO {
    #[validate(
		email(message = "O e-mail deve ser um endereço válido."),
		length(
			min = 10,
			max = 127,
			message = "O e-mail deve ter entre 10 e 127 caracteres."
		),
		regex(path = * RE_EMAIL, message = "O e-mail deve ser um endereço válido.")
	)]
    #[serde(default)]
    pub email: String,

    #[validate(
		length(
			min = 8,
			max = 255,
			message = "A senha deve ter pelo menos 8 caracteres."
		),
		regex(
			path = * RE_PASSWORD,
			message = "A senha deve ter pelo menos 1 caractere especial."
		)
	)]
    #[serde(default)]
    pub password: String,
}

#[derive(ToSchema, Serialize, Deserialize, Clone)]
pub struct DetailUserDTO {
    pub id: String,
    pub name: String,
    pub email: String,
    pub created_at: String,
}

#[derive(ToSchema, Serialize, Deserialize, Clone, Validate)]
pub struct DeleteUserDTO {
    #[validate(
		length(
			min = 8,
			max = 255,
			message = "A senha deve ter pelo menos 8 caracteres."
		),
		regex(
			path = * RE_PASSWORD,
			message = "A senha deve ter pelo menos 1 caractere especial."
		)
	)]
    #[serde(default)]
    pub password: String,
}
