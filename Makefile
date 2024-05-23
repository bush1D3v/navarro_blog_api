target:
	cargo build --release

image:
	docker build . -t bush1d3v/navarro_blog_api

push-image:
	docker push bush1d3v/navarro_blog_api