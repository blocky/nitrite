.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: lint
lint: tidy
	@golangci-lint run --config ./golangci.yaml

.PHONY: test-unit
test-unit: tidy
	@go test -short ./...

.PHONY: test-integration
test-integration: tidy
	@go test -v ./test/integration/...

TESTDATA=internal/testdata
NITRITE_CMD=cmd/nitrite/main.go
.PHONY: test-main
test-main: tidy
	@cat $(TESTDATA)/nitro_attestation.b64 | \
		go run $(NITRITE_CMD) 1>/dev/null
	@cat $(TESTDATA)/nitro_attestation_debug.b64 | \
		go run $(NITRITE_CMD) -allowdebug 1>/dev/null
	@$(shell cat $(TESTDATA)/nitro_attestation_debug.b64 | \
    	go run $(NITRITE_CMD) 2>/dev/null)
	@if [ $(.SHELLSTATUS) -eq 0 ]; then \
		echo "error\t$(NITRITE_CMD) should have failed without -allowdebug"; \
		exit 1; \
	fi
	@echo "ok\t$(NITRITE_CMD)"


some_recipe:
	@echo $(shell echo 'doing stuff'; exit 123)
	@echo 'command exited with $(.SHELLSTATUS)'
	@exit $(.SHELLSTATUS)

.PHONY: test
test: test-unit test-main

.PHONY: pre-pr
pre-pr: lint mock test

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
