FROM build-harbor.alauda.cn/ait/base-alpine:v1

COPY ./_output  /opt/output

WORKDIR /opt/output

RUN ARCH= && dpkgArch="$(arch)" \
  && case "${dpkgArch}" in \
    x86_64) ARCH='amd64';; \
    aarch64) ARCH='arm64';; \
    *) echo "unsupported architecture"; exit 1 ;; \
  esac \
  && cp linux/${ARCH}/node-manager node-manager

RUN apk add binutils && strip /opt/output/node-manager


FROM build-harbor.alauda.cn/ait/base-alpine:v1

WORKDIR /opt

COPY --from=0 /opt/output/node-manager /opt/node-manager

ENTRYPOINT ["/opt/node-manager"]
