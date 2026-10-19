# Reproducing Tempo Linux binaries

Production Docker builds and Linux release binaries use `Dockerfile.reproducible`:
Rust 1.96.0, pinned Debian packages, locked Cargo dependencies, a commit-derived
`SOURCE_DATE_EPOCH`, and the `reproducible` Cargo profile. This profile uses fat
LTO and one codegen unit, omits debug information, and retains panic unwinding.
Docker images previously used `profiling`; Linux releases previously used
`maxperf` (or the manually selected profile). Performance must be checked before
rolling these images out. The separate profiling Docker workflow keeps its
existing recipe and frame pointers.

Docker CI builds Depot candidates for amd64 and arm64 without publishing them.
Fresh GitHub-hosted runners rebuild without Depot, layer caches, compiler caches,
or precompiled Cargo artifacts. CI extracts and compares every shipped
executable, including both executables in the localnet image, before pushing any
image. Publication loads the verified archives and assembles their multi-platform
manifests; it does not compile again. The check compares executable bytes,
not full runtime image contents or image digests.

Release CI independently rebuilds both Linux architectures of `tempo` and
`tempo-sidecar`, then compares those hashes with the actual executables extracted
from the release archives and their published binary checksums. GitHub release
creation and R2 uploads depend on successful verification. Manual releases resolve
the requested ref once and use its immutable commit for both builds. macOS
binaries keep their existing native build path and are outside this reproducibility
contract; the release as a whole still waits for the Linux verification gate.

These checks separate Depot builds/caches from verification, but both are
orchestrated by GitHub Actions. They do not protect against a compromise of the
GitHub workflow itself. The periodic Argo verifiers are no longer required for
this publication gate.

## Verify a release

Check out the release tag with Git metadata and install Docker with Buildx:

```bash
VERSION=vX.Y.Z scripts/reproducible-build.sh
sha256sum out/tempo
```

Compare with `tempo-vX.Y.Z-x86_64-unknown-linux-gnu.sha256`. For arm64, build on an
arm64 Docker host with `PLATFORM=linux/arm64`. For the sidecar, set
`BINARY=tempo-sidecar FEATURES=''`. Set `NO_CACHE=1` for a fresh rebuild.

For Docker executables, use the production feature set and export target:

```bash
docker buildx build --platform linux/amd64 --no-cache --pull \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  -f Dockerfile.reproducible --target docker-artifacts \
  --output type=local,dest=out/docker .
```

Compare these executables with `/usr/local/bin/` in the corresponding published
images. `out/docker/tempo-devnet` is installed as `/usr/local/bin/tempo` in the
devnet image. The canary `reproducible-build.yml` produces a release-feature
`tempo` checksum; it is not the checksum of the Docker image's localnet-enabled
node executable.
