target:
	cargo build --release

image:
	docker build . -t bush1d3v/navarro_blog_api

push-image:
	docker push bush1d3v/navarro_blog_api

docker-build:
	docker-compose build

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose stop

docker-clean:
	docker-compose down --rmi all --volumes

run:
	RUST_LOG=debug cargo watch -x run

test:
	cargo test -- --test-threads=1

doc:
	cargo doc --open
