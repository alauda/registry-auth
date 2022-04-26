FROM build-harbor.alauda.cn/ait/builder:golang-1.15-alpine-3.14

ARG GO111MODULE="on"
ARG GONOSUMDB="gomod.alauda.cn/*"
ARG GOPROXY="https://athens.alauda.cn,direct"


COPY ./  /src

WORKDIR /src

RUN make

RUN mv _output/$(go env GOOS)/$(go env GOARCH)/registry-auth ./registry-auth

RUN strip ./registry-auth


FROM build-harbor.alauda.cn/ait/base-alpine:v1

WORKDIR /opt

COPY --from=0 /src/registry-auth /opt/registry-auth

ENTRYPOINT ["/opt/registry-auth"]
