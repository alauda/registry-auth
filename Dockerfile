ARG BASE_IMAGE="gcr.io/distroless/static:nonroot"
ARG BUILDER_IMAGE="golang:1.23-bullseye"
ARG RUN_TEST=true
ARG UID="65532"
ARG GID="65532"

FROM ${BUILDER_IMAGE} AS builder

ARG RUN_TEST
ARG UID
ARG GID

WORKDIR /go/registry-auth
COPY . /go/registry-auth

RUN make build strip
RUN cp _output/$(go env GOOS)/$(go env GOARCH)/registry-auth /usr/bin/registry-auth

RUN [ "${RUN_TEST}" != "true" ] || bash ./scripts/simple-tests.sh

FROM ${BASE_IMAGE}

ARG UID
ARG GID

WORKDIR /

COPY --from=builder /usr/bin/registry-auth /

USER ${UID}:${GID}

ENTRYPOINT ["/registry-auth"]
