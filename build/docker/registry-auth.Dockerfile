ARG OPS_DISTROLESS_TAG=20220518112439


FROM build-harbor.alauda.cn/ait/builder:golang-1.15-alpine-3.14 AS builder

ARG GO111MODULE="on"
ARG GONOSUMDB="gomod.alauda.cn/*"
ARG GOPROXY="https://athens.alauda.cn,direct"

WORKDIR /src
COPY . .

RUN make \
    && mv _output/$(go env GOOS)/$(go env GOARCH)/registry-auth ./registry-auth \
    && strip ./registry-auth

RUN mkdir -p /opt/lib
RUN case "$(arch)" in \
    x86_64) cp -rf /lib/ld-musl-x86_64.so.1 /opt/lib/;; \
    aarch64) cp -rf /lib/ld-musl-aarch64.so.1 /opt/lib/;; \
    *) echo "unsupported architecture"; exit 1 ;; \
    esac


FROM build-harbor.alauda.cn/ops/distroless-static:${OPS_DISTROLESS_TAG}
LABEL OPS_DISTROLESS_TAG="${OPS_DISTROLESS_TAG}"

COPY --from=builder /src/registry-auth /opt/registry-auth
COPY --from=builder /opt/lib /lib

WORKDIR /opt/
ENTRYPOINT ["/opt/registry-auth"]
