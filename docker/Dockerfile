# syntax=docker/dockerfile:1

# stages:
# - release: setup and builds release binaries
# - export: discrete stage for writing binaries into host build directory
# - runtime: prepares the release image
#
# We first set default values for build arguments used across the stages.
# Each stage must define the build arguments (ARGs) it uses.

ARG FEATURES=""

ARG UID=10101
ARG GID=${UID}
ARG USER="ftools"
ARG HOME="/home/${USER}"
ARG CARGO_HOME="/usr/local/.cargo"
ARG CARGO_TARGET_DIR="${HOME}/target"
ARG TARGET_ARCH="x86_64-unknown-linux-musl"

# Build dependency
FROM stagex/pallet-rust:1.94.0@sha256:2fbe7b164dd92edb9c1096152f6d27592d8a69b1b8eb2fc907b5fadea7d11668 AS pallet-rust
# Runtime Dependency
FROM stagex/core-busybox:1.37.0@sha256:d608daa946e4799cf28b105aba461db00187657bd55ea7c2935ff11dac237e27 AS busybox

# This stage builds the frost-tools release binaries.
FROM pallet-rust AS release

SHELL ["/bin/sh", "-xo", "pipefail", "-c"]

ARG HOME
WORKDIR ${HOME}

ARG CARGO_INCREMENTAL
# default to 0, disables incremental compilation.
ENV CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}

ARG CARGO_HOME
ENV CARGO_HOME=${CARGO_HOME}

ARG CARGO_TARGET_DIR
ARG TARGET_ARCH

ARG FEATURES
ENV FEATURES=${FEATURES}

ENV RUST_BACKTRACE=1
ENV RUSTFLAGS="-C codegen-units=1"
ENV RUSTFLAGS="${RUSTFLAGS} -C target-feature=+crt-static"
ENV RUSTFLAGS="${RUSTFLAGS} -C link-arg=-Wl,--build-id=none"

ENV SOURCE_DATE_EPOCH=1
ENV CXXFLAGS="-include cstdint"

RUN --mount=type=cache,target=${CARGO_HOME}/registry \
		--mount=type=cache,target=${CARGO_HOME}/git \
		--mount=type=bind,source=rust-toolchain.toml,target=rust-toolchain.toml,ro \
		--mount=type=bind,source=Cargo.toml,target=Cargo.toml,ro \
		--mount=type=bind,source=Cargo.lock,target=Cargo.lock,ro \
		--mount=type=bind,source=../frostd,target=frostd,ro \
		--mount=type=bind,source=../zcash-sign,target=zcash-sign,ro \
		--mount=type=bind,source=../frost-client,target=frost-client,ro \
		--mount=type=bind,source=../tests,target=tests,ro \
    cargo fetch --locked --target $TARGET_ARCH

RUN --network=none \
    --mount=type=cache,target=${CARGO_HOME}/registry \
		--mount=type=cache,target=${CARGO_HOME}/git \
    --mount=type=cache,target=${HOME}/target/ \
		--mount=type=bind,source=rust-toolchain.toml,target=rust-toolchain.toml,ro \
		--mount=type=bind,source=Cargo.toml,target=Cargo.toml,ro \
		--mount=type=bind,source=Cargo.lock,target=Cargo.lock,ro \
		--mount=type=bind,source=../frostd,target=frostd,ro \
		--mount=type=bind,source=../zcash-sign,target=zcash-sign,ro \
		--mount=type=bind,source=../frost-client,target=frost-client,ro \
		--mount=type=bind,source=../tests,target=tests,ro \
    cargo build --frozen --release ${FEATURES:+--features ${FEATURES}} --target ${TARGET_ARCH} && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/frostd /usr/local/bin/frostd && \
		install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/zcash-sign /usr/local/bin/zcash-sign && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/coordinator /usr/local/bin/coordinator && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/dkg /usr/local/bin/dkg && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/frost-client /usr/local/bin/frost-client && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/participant /usr/local/bin/participant && \
    install -D -m 0755 ${HOME}/target/${TARGET_ARCH}/release/trusted-dealer /usr/local/bin/trusted-dealer

# This stage is used for exporting the binaries to the host
FROM scratch AS export
COPY --from=release /usr/local/bin/* /

# This stage starts from StageX busybox and copies all the built binaries
# from the `release` stage.
FROM busybox AS runtime

# Create a non-privileged user for running `frostd` or other binaries.
#
# We use a high UID/GID (10101) to avoid overlap with host system users.
# This reduces the risk of container user namespace conflicts with host accounts,
# which could potentially lead to privilege escalation if a container escape occurs.
#
# We do not use the `--system` flag for user creation since:
# 1. System user ranges (100-999) can collide with host system users
#   (see: https://github.com/nginxinc/docker-nginx/issues/490)
# 2. There's no value added and warning messages can be raised at build time
#   (see: https://github.com/dotnet/dotnet-docker/issues/4624)
#
# The high UID/GID values provide an additional security boundary in containers
# where user namespaces are shared with the host.
ARG UID
ENV UID=${UID}
ARG GID
ENV GID=${GID}
ARG USER
ENV USER=${USER}
ARG HOME
ENV HOME=${HOME}


COPY --chmod=550 <<-EOF /etc/passwd
	root:x:0:0:root:/root:/bin/sh
	user:x:${UID}:${GID}::${HOME}:/bin/sh
EOF

COPY --chmod=550 <<-EOF /etc/group
	root:x:0:
	user:x:${GID}:
EOF

USER ${UID}:${GID}

WORKDIR /usr/local/bin

COPY --from=release /usr/local/bin/frostd /usr/local/bin/
COPY --from=release	/usr/local/bin/zcash-sign /usr/local/bin/
COPY --from=release /usr/local/bin/coordinator /usr/local/bin/
COPY --from=release	/usr/local/bin/dkg /usr/local/bin/
COPY --from=release	/usr/local/bin/frost-client /usr/local/bin/
COPY --from=release /usr/local/bin/participant /usr/local/bin/
COPY --from=release	/usr/local/bin/trusted-dealer /usr/local/bin/
COPY --chown=${UID}:${GID} ./docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
