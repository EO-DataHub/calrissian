docker ?= docker
image ?= public.ecr.aws/eodh/eodhp-calrissian
version ?= 0.1.3

.SILENT:
MAKEFLAGS += --no-print-directory

.PHONY: container-build
container-build:
	$(docker) build -t $(image):$(version) .

.PHONY: container-push
container-push:
	$(docker) push $(image):$(version)
