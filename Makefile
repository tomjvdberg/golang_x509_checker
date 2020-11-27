# Build the base image
base:
	docker build -t syvent/go_micro:base -f docker/base/Dockerfile .

#build the image and store it in the local docker repository
image:
	make base
	docker build -t syvent/go_micro -f docker/build/Dockerfile .

tests:
	make base
	docker run --rm syvent/go_micro:base go test ./... -v

# start the dev server
dev:
	make image
	docker-compose -f docker/development/docker-compose.yaml up -d && \
    docker-compose -f docker/development/docker-compose.yaml exec go_micro bash start.sh && \
    docker-compose -f docker/development/docker-compose.yaml exec go_micro bash

# open terminal in container
console:
	make image
	docker-compose -f docker/development/docker-compose.yaml up -d && \
	docker-compose -f docker/development/docker-compose.yaml exec go_micro bash

# stop running containers
down:
	docker-compose -f docker/development/docker-compose.yaml down


