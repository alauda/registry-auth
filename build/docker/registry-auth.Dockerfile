# `FROM` instructions support variables that are declared by any `ARG` instructions that occur before the first `FROM`.
ARG OPS_DISTROLESS_TAG=20220718
ARG OPS_TOOLSETS_TAG=20220726122042


FROM build-harbor.alauda.cn/ait/go-builder:1.16-alpine AS builder

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -mod vendor -buildmode=pie -ldflags '-extldflags "-Wl,-z,relro,-z,now" -linkmode=external' -a -o ./registry-auth ./cmd/registry-auth \
    && strip ./registry-auth

FROM build-harbor.alauda.cn/ops/toolset:${OPS_TOOLSETS_TAG} AS tools
FROM build-harbor.alauda.cn/ops/distroless-static:${OPS_DISTROLESS_TAG}
LABEL OPS_DISTROLESS_TAG="${OPS_DISTROLESS_TAG}"
LABEL OPS_TOOLSETS_TAG="${OPS_TOOLSETS_TAG}"

COPY --from=tools   /usr/local/bin/tail /usr/local/bin/

COPY --from=builder /src/registry-auth /opt/registry-auth

WORKDIR /opt/
ENTRYPOINT ["/opt/registry-auth"]
