.PHONY: tidy lint test-unit test-main test

tidy:
	@go mod tidy

lint: tidy
	@golangci-lint run --config ./config/golangci.yaml

test-unit: tidy
	@go test ./...

test-main: tidy
	@$(eval attestation := $(shell cat testdata/nitro_attestation.txt))
	@go run cmd/nitrite/main.go -attestation $(attestation) > /dev/null
	@echo "ok\tcmd/nitrite/main.go"

test: test-unit test-main
