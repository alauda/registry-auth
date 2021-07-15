
.PHONY: all
all: fmt vet test build

# ==============================================================================
# Build options

ROOT_PACKAGE=gomod.alauda.cn/registry-auth
VERSION_PACKAGE=gomod.alauda.cn/app/version

# ==============================================================================
# Includes

include build/lib/common.mk
include build/lib/golang.mk


# ==============================================================================
# Targets

## build: Build source code for amd64 and arm64 platform.
.PHONY: build
build:
	@$(MAKE) go.build.multiarch

.PHONY: fmt
fmt:
	@$(MAKE) go.fmt

.PHONY: vet
vet:
	@$(MAKE) go.vet

## test: Run unit test.
.PHONY: test
test:
	@$(MAKE) go.test

.PHONY: dev
dev:
	@$(MAKE) go.build.dev

