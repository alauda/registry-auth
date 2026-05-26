#!/bin/bash
REGISTRY_VERSIONS=${REGISTRY_VERSIONS:-"v2.8.1 v3.0.0"}
SKOPEO_VERSION=${SKOPEO_VERSION:-"v1.10.0"}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-"$(head -c 20 /dev/random | base64 -w 0)"}

set -xe

cd scripts

function prepare_certs() {
    openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout server.key -out server.crt -nodes -subj '/CN=registry-auth-server'
    openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout token.key -out token.crt -nodes -subj '/CN=registry-auth-token'
}

function install_registry() {
    local version="$1"
    local url="https://github.com/distribution/distribution/releases/download/${version}/registry_${version:1}_linux_$(go env GOARCH).tar.gz"
    curl -L "${url}" | tar xvz -C /usr/bin/ --exclude LICENSE --exclude READEME.md
}

function start_registry() {
    rm -rf /var/lib/registry
    REGISTRY_AUTH_TOKEN_AUTOREDIRECT=true \
    REGISTRY_AUTH_TOKEN_REALM=/auth/token \
    REGISTRY_AUTH_TOKEN_SERVICE=token-service \
    REGISTRY_AUTH_TOKEN_ISSUER=registry-token-issuer \
    REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=token.crt \
    /usr/bin/registry serve registry.yaml &
    REGISTRY_PID=$!
    # give it a moment to bind :5000
    sleep 2
}

function stop_registry() {
    if [ -n "${REGISTRY_PID}" ]; then
        kill "${REGISTRY_PID}" 2>/dev/null || true
        wait "${REGISTRY_PID}" 2>/dev/null || true
        REGISTRY_PID=""
    fi
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
    local version="$1"
    # version-tagged repo so different registry runs don't share state via the
    # client-side archive name only — push target encodes the version too.
    local repo_tag="registry-${version}"

    # prepare artifact (use a stable upstream tag; we only care that push/pull round-trips)
    skopeo copy --insecure-policy --override-os=linux \
        docker://"registry:2.8.1" \
        docker-archive:"/tmp/registry-src.tar"

    # push expecting fail (no creds)
    set +e
    skopeo copy --insecure-policy --dest-tls-verify=false \
        docker-archive:"/tmp/registry-src.tar" \
        docker://"127.0.0.1:8080/${repo_tag}:latest"

    if [ "$?" -eq "0" ]; then
        echo "push without auth against ${version} succeeded unexpectedly"
        exit 1
    fi
    set -e

    # push with auth
    skopeo copy --insecure-policy --dest-tls-verify=false --dest-creds="admin:${ADMIN_PASSWORD}" \
        docker-archive:"/tmp/registry-src.tar" \
        docker://"127.0.0.1:8080/${repo_tag}:latest"

    # pull (anonymous, since _anonymous can pull)
    skopeo copy --insecure-policy --src-tls-verify=false \
        docker://"127.0.0.1:8080/${repo_tag}:latest" \
        docker-archive:"/tmp/registry-pulled-${version}.tar"

    diff "/tmp/registry-pulled-${version}.tar" "/tmp/registry-src.tar"
}

function main() {
    prepare_certs
    prepare_skopeo
    prepare_auth
    prepare_registry_auth

    for version in ${REGISTRY_VERSIONS}; do
        echo "=== testing against distribution ${version} ==="
        install_registry "${version}"
        start_registry
        do_tests "${version}"
        stop_registry
    done
}

main
