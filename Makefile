# The idiomatic way to disable test caching explicitly is to use -count=1
GOTEST=go test -count=1 -race

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: lint
lint: tidy
	@golangci-lint run --config ./golangci.yaml

.PHONY: test-unit
test-unit: tidy
	@$(GOTEST) -short ./...

.PHONY: test-integration
test-integration: tidy
	@$(GOTEST) -v ./test/integration/...

.PHONY: test-main
test-main: tidy
	@$(GOTEST) -v ./cmd/nitrite/...

.PHONY: test
test: test-unit test-integration test-main

.PHONY: pre-pr
pre-pr: mock lint test

.PHONY: mock
mock: tidy
	@rm -rf mocks
	@mockery --quiet --config=mockery.yaml

.PHONY: very_clean
very_clean:
	@rm -rf mocks
