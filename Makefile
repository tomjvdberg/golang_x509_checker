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

#build the image and store it in the local docker repository
image:
	docker build -t syvent/go_micro -f docker/build/Dockerfile .
