# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`registry-auth` is a Go service that provides authentication and authorization for the [Docker Registry](https://github.com/distribution/distribution). It implements two of the Registry's auth flows:

- **Token auth**: Registry-auth runs alongside the Registry. The client first hits the Registry, gets a 401 with the `WWW-Authenticate` URL, then exchanges Basic credentials at `/auth/token` for a JWT that the Registry verifies against the shared certificate.
- **Proxy auth**: Registry-auth sits in front of the Registry. It accepts Basic auth on `/v2/*`, mints a token internally, swaps it onto the request's `Authorization` header, and reverse-proxies to the Registry backend.

Both flows share the same JWT signer; the Docker Registry must be configured with the same `rootcertbundle` and `issuer` as registry-auth's `--auth-public-cert-file` and `--auth-issuer`.

## Common commands

```bash
make build              # build _output/<os>/<arch>/registry-auth (CGO_ENABLED=0)
make test               # go test -v -cover ./...
make fmt vet            # gofmt + go vet
make image              # docker build -> ghcr.io/alauda/registry-auth:<version>
make all                # fmt + vet + test + build + strip

# Single test (no shortcut in Makefile)
go test -v ./pkg/server -run TestHandleAuth

# End-to-end integration test — pulls a real registry binary + skopeo, runs
# registry-auth, push/pull image. Used by the Dockerfile's RUN_TEST stage.
# Requires curl, openssl, go, and root-ish perms to write /usr/bin. Run from repo root.
bash scripts/simple-tests.sh
```

The version string baked into the binary comes from `git describe`; building from a detached or dirty tree marks `GitTreeState=dirty`.

## Architecture

### Layered entrypoint

`cmd/registry-auth/main.go` → `cmd/registry-auth/app/app.go` wires together option groups and calls `pkg/app.NewApp`. `pkg/app` is a small cobra+viper+pflag harness shared across Alauda apps:

- `Options` (`pkg/server/options/interface.go`) aggregates a list of `Optioner`s; each option group owns its flags, viper bindings, and an `ApplyToServer` hook.
- `app.runCommand` calls `ApplyFlags` (CLI → struct), then `ApplyToServer` (struct → `*server.Server`), then `server.Start`.
- To add a new flag, add it to an existing options file under `pkg/server/options/` (or create a new `Optioner` and register it in `cmd/registry-auth/app/app.go`).

### Server

`pkg/server/server.go` holds the long-lived `Server`. `ApplyToServer` wires routes onto a `go-restful` container:

- `GET /auth/token` → `HandleAuth` (token mode)
- `/v2/*` → `HandleProxy` (proxy mode; reverse-proxies to `--registry-backend`)
- `/health` → static OK

Both modes funnel through `Server.signToken` (`pkg/server/handlers.go`), which calls `AuthProcessor.Authenticate` → `Authorize` → `Sign`.

### AuthProcessor (`pkg/server/auth.go`)

The single source of auth truth. It holds two parallel sets of user/auth maps:

- `StaticUsers` / `StaticAuths` — populated from the YAML/JSON file (`--auth-config-file`).
- `SecretUsers` / `SecretAuths` — populated from Kubernetes Secrets (`--auth-config-namespace` + `--auth-config-selector`).

**Lookup order** in both `Authenticate` and `Authorize`: Secret first, then Static, then third-party (`pkg/server/thirdparty.go`). If a request's user has no matching authorization, `signToken` retries authorization as the special `_anonymous` user — that's how unauthenticated pulls are configured.

Password verification supports three formats in this priority: bcrypt (`$...`), reserved `PBKDF2:` prefix (not implemented), and plaintext fallback. Use `htpasswd -nbB user pass` to generate bcrypt hashes.

`DecodeScope` parses the `scope=` query parameter (token mode). `DecodeScopeFromUrl` infers `type:name:actions` from the URL/method (proxy mode); HTTP methods map to actions as GET/HEAD→`pull`, PUT/PATCH/POST→`push`, DELETE→`delete`. `/v2/_catalog` uses `registry:catalog:*`.

In proxy mode `IsScopeActionMatch` short-circuits: if the request's actions are already a subset of what was granted, `signToken` returns `ErrNotHandleAuthHeader` and the handler leaves the existing `Authorization` header alone (avoids re-signing on every blob request).

### Config sources (all watched live)

- `file.go` — `fsnotify` watcher on `--auth-config-file`. Calls `LoadFromFile` on Create/Write events.
- `secret.go` — client-go informer over Secrets in `--auth-config-namespace` matching `--auth-config-selector` (default `registry-auth-config=true`). The Secret's `config` key contains the same YAML schema as the file. Add/Update/Delete events are reflected into `SecretUsers`/`SecretAuths` via `LoadFromSecret`.
- `thirdparty.go` — `--auth-thirdparty-server` URL. Registry-auth POSTs Basic-auth'd login requests there; the response is a list of `Authorization` entries cached per user. Only consulted when the user is in neither map.

### JWT signing

`NewAuthProcessor` parses the public cert (`loadCert`) and constructs a `jose.Signer` with RS256, emitting the signing cert as a JWS `x5c` header (`encoding/base64` StdEncoding of `cert.Raw`). The private key must be RSA. Claims include `iss`, `sub`, `aud` (from `?service=` or `--service`), `exp`, `nbf`, `iat`, `jti`, and the `access` array.

Why `x5c` and not `kid`: distribution v2 keys its `trustedKeys` map by `libtrust.KeyID()` (libtrust is archived), while distribution v3 keys it by RFC 7638 JWK thumbprint — the two formats don't agree. Both versions, however, first verify the JWT's `x5c` cert chain against the `rootcertbundle`, so emitting `x5c` makes tokens accepted by both v2.x and v3.x without depending on libtrust.

## Configuration schema

`auth-config-file` and the `config` key of watched Secrets share this YAML schema:

```yaml
users:
  user1: plaintext-password
  user2: $2y$05$...bcrypt-hash
auths:
  user1:
    - target: repo/path        # literal match
      actions: [pull, push]
    - target: team/.*          # regex match
      useRegexp: true
      actions: [pull]
  _anonymous:                  # fallthrough for unauthenticated or unmatched users
    - target: .*
      useRegexp: true
      actions: [pull]
```

`Authorization.Type` defaults to `repository` if omitted; set it to `registry` for catalog-scoped grants.

## Notes / gotchas

- `BasicOptions.ApplyToServer` (`pkg/server/options/basic.go:130`) assigns `o.AuthConfigNamespace` into `server.BasicConfig.AuthConfigLabelSelector` — looks like a copy-paste bug. Selector configured via the flag will not reach the server. If you touch this code, fix to use `o.AuthConfigLabelSelector`.
- `AuthProcessor.LoadFromSecret` (`pkg/server/auth.go:295`) reads `dataOld[SecretKey]` when populating new entries (should be `dataNew`). Updates to Secrets may not behave as expected — verify before relying on dynamic Secret updates.
- The `go.mod` pins `k8s.io/client-go` to `v0.24.4` via `replace`; other `k8s.io/*` deps must stay compatible with that version.
- `pkg/server/auth.go` still uses `io/ioutil`; that's fine, just don't "modernize" mid-task without reason.
- Tokens are verified via `x5c` (not `kid`). Don't reintroduce `libtrust` or a `kid` header without also handling v2/v3 thumbprint differences — see the JWT signing section above.
