.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: lint
lint: tidy
	@golangci-lint run --config ./golangci.yaml

.PHONY: test-unit
test-unit: tidy
	@go test ./...

.PHONY: test-main
test-main: tidy
	@$(eval attestation := $(shell cat testdata/nitro_attestation.b64))
	@go run cmd/nitrite/main.go -attestation $(attestation) > /dev/null
	@echo "ok\tcmd/nitrite/main.go"

.PHONY: test
test: test-unit test-main

.PHONY: pre-pr
pre-pr: lint test

.PHONY: mock
mock: tidy
# There is a corner case where removing all mocks before regenerating them can
# cause a deadlock. If you introduce a new package dependency to your code and
# then delete mocks, then you can't run `go mod tidy` because mocks are missing
# and you can't run `mockery` because of a missing dependency.
# To avoid this, we first run `mockery --dry-run` to see if mocks can be
# regenerated. If that command fails, the `mock` target stops execution.
	@mockery --dry-run --config=mockery.yaml
# If we can regenerate mocks, remove all mocks and generate, to make sure old
# mocks purged.
	@rm -rf mocks
	@mockery --quiet --config=mockery.yaml

.PHONY: very_clean
very_clean:
	@rm -rf mocks
