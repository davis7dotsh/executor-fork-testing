# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH

FROM oven/bun:1.3.11@sha256:0733e50325078969732ebe3b15ce4c4be5082f18c4ac1a0f0ca4839c2e4e42a7 AS web-builder

ARG TARGETARCH

WORKDIR /build

COPY package.json bun.lock ./
COPY patches ./patches
COPY apps ./apps
COPY e2e ./e2e
COPY examples ./examples
COPY legacy ./legacy
COPY packages ./packages
COPY web/package.json ./web/package.json

RUN --mount=type=cache,id=executor-bun-${TARGETARCH},target=/root/.bun/install/cache,sharing=locked \
    bun install --frozen-lockfile --ignore-scripts --filter @executor-js/web

COPY web ./web
RUN bun run --cwd web build


FROM rust:1.96-bookworm@sha256:6d19f49541d185805745b8baa781b1fd482118c81a3154510ee18dcce985d005 AS rust-builder

ARG TARGETARCH

WORKDIR /build

COPY Cargo.toml Cargo.lock build.rs LICENSE about.toml about.hbs ./
COPY migrations ./migrations
COPY packaging/launchd/bounded-log.sh ./packaging/launchd/bounded-log.sh
COPY packaging/launchd/dev.executor.gateway.plist ./packaging/launchd/dev.executor.gateway.plist
COPY packaging/systemd/executor.env.example ./packaging/systemd/executor.env.example
COPY packaging/systemd/executor.service ./packaging/systemd/executor.service
COPY scripts/install-launchd.sh ./scripts/install-launchd.sh
COPY scripts/install-systemd.sh ./scripts/install-systemd.sh
COPY scripts/lib/install-systemd-master-key.sh ./scripts/lib/install-systemd-master-key.sh
COPY src ./src
COPY --from=web-builder /build/web/build ./web/build

RUN --mount=type=cache,id=executor-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=executor-cargo-target-${TARGETARCH},target=/build/target,sharing=locked \
    cargo install cargo-about --version 0.9.0 --locked && \
    cargo about generate about.hbs > THIRD_PARTY_LICENSES.html && \
    cargo build --locked --release && \
    cp target/release/executor /usr/local/bin/executor


FROM debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime-base

ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT=20260623T000000Z
ARG EXECUTOR_UID=10001
ARG EXECUTOR_GID=10001

RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm bookworm-updates' \
      'Components: main' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm-security' \
      'Components: main' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install --yes --no-install-recommends ca-certificates curl && \
    rm -rf \
      /var/cache/ldconfig/aux-cache \
      /var/lib/apt/lists/* \
      /var/log/apt/* \
      /var/log/dpkg.log && \
    groupadd --gid "${EXECUTOR_GID}" executor && \
    useradd --uid "${EXECUTOR_UID}" --gid executor --no-create-home \
      --home-dir /var/lib/executor --shell /usr/sbin/nologin executor && \
    chage --lastday \
      "$(date --utc --date="@${SOURCE_DATE_EPOCH:-0}" +%Y-%m-%d)" \
      executor && \
    install --directory --owner executor --group executor --mode 0700 \
      /var/lib/executor && \
    install --directory --owner root --group executor --mode 0750 \
      /etc/executor

ENV EXECUTOR_DATA_DIR=/var/lib/executor \
    EXECUTOR_PUBLIC_ORIGIN=http://127.0.0.1:4788 \
    RUST_LOG=executor=info

USER executor:executor
WORKDIR /var/lib/executor

EXPOSE 4788
VOLUME ["/var/lib/executor"]
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:4788/healthz"]

ENTRYPOINT ["/usr/local/bin/executor"]
CMD ["server", "--bind", "0.0.0.0:4788", "--allow-unsafe-http-non-loopback"]


# Release automation supplies the extracted Linux archive as the named
# prebuilt-executor context. This target never compiles web or Rust code.
FROM runtime-base AS runtime-prebuilt

COPY --from=prebuilt-executor --chmod=0755 /executor /usr/local/bin/executor
COPY --from=prebuilt-executor --chmod=0644 /LICENSE /usr/share/licenses/executor/LICENSE
COPY --from=prebuilt-executor --chmod=0644 /THIRD_PARTY_LICENSES.html /usr/share/licenses/executor/THIRD_PARTY_LICENSES.html
COPY --from=prebuilt-executor --chmod=0644 /THIRD_PARTY_JAVASCRIPT_LICENSES.json /usr/share/licenses/executor/THIRD_PARTY_JAVASCRIPT_LICENSES.json


# Keep the default target self-contained for local and CI builds.
FROM runtime-base AS runtime

COPY --from=rust-builder /usr/local/bin/executor /usr/local/bin/executor
COPY --from=rust-builder /build/LICENSE /usr/share/licenses/executor/LICENSE
COPY --from=rust-builder /build/THIRD_PARTY_LICENSES.html /usr/share/licenses/executor/THIRD_PARTY_LICENSES.html
COPY --from=rust-builder /build/web/build/THIRD_PARTY_JAVASCRIPT_LICENSES.json /usr/share/licenses/executor/THIRD_PARTY_JAVASCRIPT_LICENSES.json
