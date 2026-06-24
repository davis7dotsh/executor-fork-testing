# syntax=docker/dockerfile:1.7

FROM oven/bun:1.3.11 AS web-builder

ARG TARGETARCH

WORKDIR /build

COPY package.json bun.lock ./
COPY patches ./patches
COPY web/package.json ./web/package.json

RUN --mount=type=cache,id=executor-bun-${TARGETARCH},target=/root/.bun/install/cache,sharing=locked \
    bun install --frozen-lockfile --ignore-scripts --filter @executor-js/web

COPY web ./web
RUN bun run --cwd web build


FROM rust:1.96-bookworm AS rust-builder

ARG TARGETARCH

WORKDIR /build

COPY Cargo.toml Cargo.lock build.rs LICENSE about.toml about.hbs ./
COPY migrations ./migrations
COPY src ./src
COPY --from=web-builder /build/web/build ./web/build

RUN --mount=type=cache,id=executor-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=executor-cargo-target-${TARGETARCH},target=/build/target,sharing=locked \
    cargo install cargo-about --version 0.9.0 --locked && \
    cargo about generate about.hbs > THIRD_PARTY_LICENSES.html && \
    cargo build --locked --release && \
    cp target/release/executor /usr/local/bin/executor


FROM debian:bookworm-slim AS runtime

ARG EXECUTOR_UID=10001
ARG EXECUTOR_GID=10001

RUN apt-get update && \
    apt-get install --yes --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid "${EXECUTOR_GID}" executor && \
    useradd --uid "${EXECUTOR_UID}" --gid executor --no-create-home \
      --home-dir /var/lib/executor --shell /usr/sbin/nologin executor && \
    install --directory --owner executor --group executor --mode 0700 \
      /var/lib/executor /etc/executor

COPY --from=rust-builder /usr/local/bin/executor /usr/local/bin/executor
COPY --from=rust-builder /build/LICENSE /usr/share/licenses/executor/LICENSE
COPY --from=rust-builder /build/THIRD_PARTY_LICENSES.html /usr/share/licenses/executor/THIRD_PARTY_LICENSES.html
COPY --from=rust-builder /build/web/build/THIRD_PARTY_JAVASCRIPT_LICENSES.json /usr/share/licenses/executor/THIRD_PARTY_JAVASCRIPT_LICENSES.json

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
