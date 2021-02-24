SHELL := /bin/bash

run:
	go run app/sales-api/main.go

admin:
	go run app/admin/main.go

tidy:
	go mod tidy
	go mod vendor