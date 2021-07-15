FROM centos:7

ARG PKG=conntrack-tools
ARG KUBE_VERSION=v1.19.9
ARG CNI_PLUGIN_VERSION=v0.8.6

RUN yum install wget yum-utils -y 
RUN ARCH= && dpkgArch="$(arch)" \
    && case "${dpkgArch}" in \
        x86_64) ARCH='amd64';; \
        aarch64) ARCH='arm64';; \
        *) echo "unsupported architecture"; exit 1 ;; \
        esac \
    && wget -c "https://dl.k8s.io/${KUBE_VERSION}/kubernetes-node-linux-${ARCH}.tar.gz" -O /kubernetes-node.tar.gz \
    && wget -c "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-linux-${ARCH}-${CNI_PLUGIN_VERSION}.tgz" -O "cni-plugins.tar.gz"

RUN RPM_DIR=$(mktemp -d) \
    && INSTALL_DIR=$(mktemp -d) \
    && yumdownloader --resolve --destdir=${RPM_DIR} ${PKG} \
    && cd ${INSTALL_DIR} \
    && for rpm in ${RPM_DIR}/*.rpm; do rpm2cpio $rpm | cpio -idm; done \
    && tar -cvzf /${PKG}.tar.gz *

FROM build-harbor.alauda.cn/ait/base-alpine:v1

COPY --from=0 /kubernetes-node.tar.gz /cni-plugins.tar.gz /conntrack-tools.tar.gz /
