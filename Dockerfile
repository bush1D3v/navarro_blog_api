FROM rust:1.78.0-alpine

RUN apk update && apk add cmake g++

WORKDIR /actix

RUN mkdir src; touch src/main.rs

COPY Cargo.toml Cargo.lock ./

RUN cargo fetch

COPY src/ ./src/

RUN cargo build --release

EXPOSE 80

CMD ./target/release/navarro_blog_api