
GO := go
OS := $(shell $(GO) env GOOS)
ARCH := $(shell $(GO) env GOARCH)
COMMAND := registry-auth
VERSION_PACKAGE := github.com/alauda/registry-auth/pkg/app/version

ifeq ($(origin VERSION), undefined)
	VERSION := $(shell git describe --dirty --always --tags | sed 's/-/./g')
endif
GIT_TREE_STATE := "dirty"
ifeq (, $(shell git status --porcelain 2>/dev/null))
	GIT_TREE_STATE = "clean"
endif
GIT_COMMIT := $(shell git rev-parse HEAD)

GO_LDFLAGS += -X $(VERSION_PACKAGE).GitVersion=$(VERSION) \
			  -X $(VERSION_PACKAGE).GitCommit=$(GIT_COMMIT) \
			  -X $(VERSION_PACKAGE).GitTreeState=$(GIT_TREE_STATE) \
			  -X $(VERSION_PACKAGE).BuildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

DOCKER_BUILD_ARGS := ""

.PHONY: all
all: fmt vet test build strip

.PHONY: build
build: fmt vet
	@echo "===========> Building binary $(COMMAND) $(VERSION) for $(OS) $(ARCH)"
	@mkdir -p _output/$(OS)/$(ARCH)
	@CGO_ENABLED=0 $(GO) build -a -o _output/$(OS)/$(ARCH)/${COMMAND} -ldflags "$(GO_LDFLAGS)" ./cmd/${COMMAND}

.PHONY: image
image:
	@docker build -t gchr.io/alauda/registry-auth:$(VERSION) ${DOCKER_BUILD_ARGS} .

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	@echo "===========> Run unit test"
	$(GO) test -v -cover ./...


.PHONY: strip
strip:
	@echo "===========> Strip binary $(COMMAND) $(VERSION) for $(OS) $(ARCH)"
	@strip _output/$(OS)/$(ARCH)/$(COMMAND)
