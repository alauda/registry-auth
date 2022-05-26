# `FROM` instructions support variables that are declared by any `ARG` instructions that occur before the first `FROM`.
ARG OPS_DISTROLESS_TAG=20220518112439
ARG OPS_TOOLSETS_TAG=20220526181103


FROM build-harbor.alauda.cn/ait/builder:golang-1.15-alpine-3.14 AS builder

ARG GO111MODULE="on"
ARG GONOSUMDB="gomod.alauda.cn/*"
ARG GOPROXY="https://athens.alauda.cn,direct"

WORKDIR /src
COPY . .

RUN make \
    && mv _output/$(go env GOOS)/$(go env GOARCH)/registry-auth ./registry-auth \
    && strip ./registry-auth


FROM build-harbor.alauda.cn/ops/toolset:${OPS_TOOLSETS_TAG} AS tools
FROM build-harbor.alauda.cn/ops/distroless-static:${OPS_DISTROLESS_TAG}
LABEL OPS_DISTROLESS_TAG="${OPS_DISTROLESS_TAG}"
LABEL OPS_TOOLSETS_TAG="${OPS_TOOLSETS_TAG}"

COPY --from=tools   /usr/local/bin/tail /usr/local/bin/
# 拷贝 ld-musl-x86_64.so.1 或 ld-musl-aarch64.so.1 文件
COPY --from=tools   /lib/               /lib/

COPY --from=builder /src/registry-auth /opt/registry-auth

WORKDIR /opt/
ENTRYPOINT ["/opt/registry-auth"]
