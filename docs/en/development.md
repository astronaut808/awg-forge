# Development

## Requirements

- Go `1.26.7`;
- Node.js `24.x` and npm for building the Web UI;
- Deno `2.x` for frontend source linting;
- `golangci-lint` `2.x` for Go linting;
- Docker for image/runtime testing.

## Common Commands

```bash
make test
make test-race
make vet
make build
make ui-check
make ui-build
make api-contract
make lint-go
make lint-js
make lint-shell
make lint-docker
make lint-actions
make lint-actions-security
make quality
make ci
make security
make security-fast
make docker-build
make docker-smoke IMAGE=awg-forge:local
```

## Local UI Run

For local development, runtime tunnel changes usually do not need to be applied:

```bash
CONFIG_DIR=/private/tmp/awg-forge-dev \
WEBUI_HOST=127.0.0.1 \
WEBUI_PORT=51821 \
PASSWORD=test \
APPLY_CONFIG=false \
go run ./cmd/awg-forge serve
```

Open:

```text
http://127.0.0.1:51821
```

The standard Docker image includes the experimental AWG 3.x userspace runtime.
For a local no-apply UI review, expose the same compiled capability explicitly:

```bash
CONFIG_DIR=/private/tmp/awg-forge-dev \
WEBUI_HOST=127.0.0.1 \
WEBUI_PORT=51821 \
PASSWORD=test \
APPLY_CONFIG=false \
go run -ldflags='-X github.com/astronaut808/awg-forge/internal/buildinfo.AWG3Runtime=true' ./cmd/awg-forge serve
```

Keep `APPLY_CONFIG=false`. A local `go run` does not install the pinned AWG 3.x
runtime tools shipped in the standard Docker image.

## Pre-commit Checks

```bash
make ci
git diff --check
```

`make ci` runs:

- `go test ./...`;
- `go vet ./...`;
- `go build ./...`;
- `golangci-lint run`;
- `npm run ui:check`;
- `npm run ui:build`;
- `make api-contract`, which parses the OpenAPI source and checks the documented core control-plane routes and error envelope;
- `deno lint web/src`;
- `npm run quality:aislop`, which runs `aislop ci` with the project `.aislop/config.yml`.

Pull requests also run separate `Security`, `Race`, and Docker image validation jobs. The security job runs `govulncheck`, Gitleaks, focused Semgrep and Trivy filesystem scans, ShellCheck, Hadolint, actionlint, and offline pedantic zizmor analysis. The Docker job starts the built image with runtime apply disabled, authenticates to the API, verifies the bundled AmneziaWG binaries and rendered config parser, restarts the container, and checks that the tunnel configuration remains available and parseable.

The Aislop CI gate currently fails below score `80`. The config excludes reproducible generated Web UI assets and locale dictionaries that produce scanner-only noise. Keep source warnings visible unless a finding is a documented false positive.

## Security Checks

Run the release security gate before publishing a version:

```bash
make security
```

`make security` runs `govulncheck` against AWG-Forge and the root daemon package at the exact `AMNEZIAWG_GO_REF`, plus ShellCheck, Hadolint, actionlint, zizmor, Gitleaks, Trivy, and the full Semgrep registry rules. It may need network access for the pinned upstream source, Go tools, scanner databases, and rules. Zizmor complements actionlint by checking workflow permissions, unsafe triggers, mutable action references, untrusted input handling, and other GitHub Actions security properties.

For a faster local check:

```bash
make security-fast
```

The fast gate uses focused Semgrep rules and HIGH/CRITICAL Trivy findings. Gitleaks scans history reachable from `HEAD` locally; pull requests restrict it to the PR commit range. Docker image validation blocks fixed HIGH/CRITICAL operating-system package vulnerabilities. Application dependency findings remain informational; the blocking source checks separately determine reachability in AWG-Forge and the exact pinned AmneziaWG daemon instead of rejecting unused packages from the wider upstream module.

The two Semgrep findings that require a final non-root `USER` are suppressed only on the affected `ENTRYPOINT` and `CMD` instructions in the runtime Dockerfile. AWG-Forge intentionally runs as root with the Compose-granted capabilities because it manages host-network TUN interfaces, routes, and firewall rules. Removing root safely requires splitting those operations into a separate privileged helper; repository-wide rule exclusions would hide findings in future Dockerfiles and are not permitted.

Run the same non-privileged image smoke test used for pull requests after building a local image:

```bash
make docker-build
make docker-smoke IMAGE=awg-forge:local
```

Generated frontend assets under `internal/server/static/assets/` and embedded fonts are excluded from Semgrep. The source of truth is `web/src/`; generated output is verified by `npm run ui:build` and `git diff --exit-code -- internal/server/static`.

## Frontend

Frontend source lives in `web/` and is built with Vite + Preact + TypeScript.

Generated output lives in `internal/server/static/` and is embedded into the Go binary with `embed.FS`. Update generated files with:

```bash
npm install
npm run ui:build
```

For frontend dev server:

```bash
npm run ui:dev
```

`ui:dev` proxies `/api` and `/clients` to the local backend at `127.0.0.1:51821`.

The runtime and Docker image do not require Node/npm/Deno. These tools are development and CI-only.

## Backend

Main areas:

- `cmd/awg-forge`: CLI entrypoint;
- `internal/app`: service layer, state mutations, rollback, rendering/apply orchestration;
- `internal/backup`: encrypted backup and restore validation;
- `internal/config`: env/state model;
- `internal/firewall`: managed iptables check/repair model;
- `internal/protocol`: protocol profiles and validation;
- `internal/render`: server/client config rendering;
- `internal/server`: Web UI/API;
- `internal/doctor`: diagnostics;
- `internal/support`: secret-free support bundle generation;
- `internal/updates`: AmneziaWG upstream update checks.
