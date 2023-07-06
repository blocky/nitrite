GOFLAGS=-mod=mod
GO=GOFLAGS=$(GOFLAGS) go
GOMOD=$(GO) mod
GOTEST=$(GO) test -count=1
GOTIDY=$(GOMOD) tidy
GOFMT=gofmt -s
GOFMT_FORMAT=$(GOFMT) -w
PKG=./pkg

format:
	@$(GOFMT_FORMAT) .

lint:
	@golangci-lint run --config ./config/golangci.yaml

mock:
	@mockery

mock-clean:
	@find . -type f -name 'mock_*.go' -delete

pre-pr: mock test-unit lint

test-unit: test-unit-package

test-unit-package:
	@(cd $(PKG) && \
		$(GOTEST) ./...	&& \
		$(GOTIDY))