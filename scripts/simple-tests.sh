#!/bin/bash
REGISTRY_VERSION=${REGISTRY_VERSION:-"v2.8.1"}
SKOPEO_VERSION=${SKOPEO_VERSION:-"v1.10.0"}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-"$(head -c 20 /dev/random | base64 -w 0)"}

set -xe

cd scripts

function prepare_certs() {
    openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout server.key -out server.crt -nodes -subj '/CN=registry-auth-server'
    openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout token.key -out token.crt -nodes -subj '/CN=registry-auth-token'
}

function prepare_registry() {
    local url="https://github.com/distribution/distribution/releases/download/${REGISTRY_VERSION}/registry_${REGISTRY_VERSION:1}_linux_$(go env GOARCH).tar.gz"
    curl -L "${url}" | tar xvz -C /usr/bin/ --exclude LICENSE --exclude READEME.md
    pwd
    ls
    REGISTRY_AUTH_TOKEN_AUTOREDIRECT=true \
    REGISTRY_AUTH_TOKEN_REALM=/auth/token \
    REGISTRY_AUTH_TOKEN_SERVICE=token-service \
    REGISTRY_AUTH_TOKEN_ISSUER=registry-token-issuer \
    REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=token.crt \
    /usr/bin/registry serve registry.yaml &
}

function prepare_skopeo() {
    local url="https://github.com/containers/skopeo/archive/refs/tags/${SKOPEO_VERSION}.tar.gz"
    mkdir -p /go/skopeo
    curl -L "${url}" | tar xz -C /go
    cd /go/skopeo-${SKOPEO_VERSION:1}
    ENABLE_CGO=0 GO111MODULE=on go build -mod=vendor "-buildmode=pie" -o /usr/bin/skopeo -tags 'exclude_graphdriver_devicemapper exclude_graphdriver_btrfs containers_image_openpgp' ./cmd/skopeo
    cd -
}

function prepare_auth() {
    cat <<EOF > ./auth.yaml
users:
  admin: ${ADMIN_PASSWORD}
auths:
  admin:
  - target: .*
    useRegexp: true
    actions:
    - pull
    - push
  _anonymous:
  - target: .*
    useRegexp: true
    actions:
    - pull
EOF
}

function prepare_registry_auth() {
  /usr/bin/registry-auth \
        --server-tls-cert-file=server.crt \
        --server-tls-key-file=server.key \
        --auth-public-cert-file=token.crt \
        --auth-private-key-file=token.key \
        --auth-config-file=auth.yaml &
}

function do_tests() {

    # prepare artificat
    skopeo copy --insecure-policy --override-os=linux \
        docker://"registry:${REGISTRY_VERSION:1}" \
        docker-archive:"/tmp/registry-${REGISTRY_VERSION}.tar" \

    # push expecting fail
    set +e
    skopeo copy --insecure-policy --dest-tls-verify=false \
        docker-archive:"/tmp/registry-${REGISTRY_VERSION}.tar" \
        docker://"127.0.0.1:8080/registry:${REGISTRY_VERSION}"

    if [ "$?" -eq "0" ]; then
        echo "push without auth failed"
        exit -1
    fi
    set -e

    # push with auth
    skopeo copy --insecure-policy --dest-tls-verify=false --dest-creds="admin:${ADMIN_PASSWORD}" \
        docker-archive:"/tmp/registry-${REGISTRY_VERSION}.tar" \
        docker://"127.0.0.1:8080/registry:${REGISTRY_VERSION}" \

    # pull
    skopeo copy --insecure-policy --src-tls-verify=false \
        docker://"127.0.0.1:8080/registry:${REGISTRY_VERSION}" \
        docker-archive:"/tmp/registry-${REGISTRY_VERSION}-local.tar"


    diff "/tmp/registry-${REGISTRY_VERSION}-local.tar" "/tmp/registry-${REGISTRY_VERSION}.tar"

}

function main() {
    prepare_certs
    prepare_registry
    prepare_skopeo
    prepare_auth
    prepare_registry_auth
    do_tests
}

main
