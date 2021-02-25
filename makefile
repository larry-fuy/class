SHELL := /bin/bash

# ==============================================================================
# Building containers

all: sales-class

sales-class:
	docker build \
		-f zarf/docker/dockerfile.sales-api \
		-t sales-api-amd64:1.0 \
		--build-arg VCS_REF=`git rev-parse HEAD` \
		--build-arg BUILD_DATE=`date -u +”%Y-%m-%dT%H:%M:%SZ”` \
		.

run:
	go run app/sales-api/main.go

admin:
	go run app/admin/main.go

test:
	go test ./...

tidy:
	go mod tidy
	go mod vendor