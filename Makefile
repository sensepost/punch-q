# ref: https://vic.demuzere.be/articles/golang-makefile-crosscompile/

default: run-docker

docker-dev:
	docker build -t punch-q:dev -f Dockerfile.dev .

docker:
	docker build -t punch-q:local .

run-docker-dev:
	docker run --rm -it -v $(pwd):/punch-q punch-q:dev

run-docker:
	docker run --rm -it -v $(pwd):/data punch-q:local
