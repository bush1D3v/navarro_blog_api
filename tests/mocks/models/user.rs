use navarro_blog_api::dtos::user::CreateUserDTO;

pub fn user() -> CreateUserDTO {
    return CreateUserDTO {
        name: String::from("Victor Navarro"),
        email: String::from("bush1d3v@gmail.com"),
        password: String::from("12345678%"),
    };
}
