# `FROM` instructions support variables that are declared by any `ARG` instructions that occur before the first `FROM`.
ARG OPS_DISTROLESS_TAG=20220422

FROM build-harbor.alauda.cn/ait/builder:golang-1.15-alpine-3.14 AS builder

ARG GO111MODULE="on"
ARG GONOSUMDB="gomod.alauda.cn/*"
ARG GOPROXY="https://athens.alauda.cn,direct"

WORKDIR /src/
COPY . .

RUN make \
    && mv _output/$(go env GOOS)/$(go env GOARCH)/registry-auth ./registry-auth \
    && strip ./registry-auth


FROM build-harbor.alauda.cn/ops/distroless-static:${OPS_DISTROLESS_TAG}

WORKDIR /opt/
COPY --from=builder /src/registry-auth /opt/

ENTRYPOINT ["/opt/registry-auth"]
