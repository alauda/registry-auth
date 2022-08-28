ARG BASE_IMAGE="gcr.io/distroless/static:nonroot"
ARG BUILDER_IMAGE="golang:1.18-bullseye"

FROM ${BUILDER_IMAGE} AS builder

WORKDIR /go/registry-auth
COPY . /go/registry-auth

RUN make build strip
RUN cp _output/$(go env GOOS)/$(go env GOARCH)/registry-auth /opt/registry-auth


FROM ${BASE_IMAGE}

WORKDIR /

COPY --from=builder /opt/registry-auth /

USER 65532:65532

ENTRYPOINT ["/registry-auth"]
