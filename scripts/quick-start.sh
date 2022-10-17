#!/bin/bash

# generate certificates
openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout server.key -out server.crt -nodes -subj '/CN=registry-auth-server'
openssl req -new -newkey rsa:2048 -days 365 -x509 -keyout token.key -out token.crt -nodes -subj '/CN=registry-auth-token'

# generate a demo auth config
# only admin can push images but anyone can pull images
cat <<EOF > ./auth.yaml
users:
  admin: admin
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

# run Registry-Auth
docker run -d --name registry-auth -p 8080:8080 \
  -v $(pwd):/etc/registry-auth \
  ghcr.io/alauda/registry-auth:latest \
  --server-tls-cert-file=/etc/registry-auth/server.crt \
  --server-tls-key-file=/etc/registry-auth/server.key \
  --auth-public-cert-file=/etc/registry-auth/token.crt \
  --auth-private-key-file=/etc/registry-auth/token.key \
  --auth-config-file=/etc/registry-auth/auth.yaml

# run docker registry
docker run -d \
  --name registry \
  --network container:registry-auth \
  -v $(pwd)/token.crt:/etc/registry-auth/token.crt \
  -e REGISTRY_AUTH_TOKEN_AUTOREDIRECT=true \
  -e REGISTRY_AUTH_TOKEN_REALM=/auth/token \
  -e REGISTRY_AUTH_TOKEN_SERVICE=token-service \
  -e REGISTRY_AUTH_TOKEN_ISSUER=registry-token-issuer \
  -e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/etc/registry-auth/token.crt \
  registry:2.8

# tests

docker login 127.0.0.1:8080 -u admin -p admin
docker tag registry:2.8 127.0.0.1:8080/registry:2.8
docker push 127.0.0.1:8080/registry:2.8
docker logout 127.0.0.1:8080
docker rmi 127.0.0.1:8080/registry:2.8
docker pull 127.0.0.1:8080/registry:2.8
