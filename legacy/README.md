# Legacy products

This directory contains all previous TypeScript application entry points. The
active product is the local/self-hosted Rust server and Svelte dashboard in the
repository root and `web/`.

The legacy packages remain in the Bun workspace so their dependency graph and
historical end-to-end scenarios stay reproducible. They are excluded from the
default development, test, typecheck, lint, format, and CI paths. Use the root
`legacy:dev`, `legacy:dev:cli`, `legacy:test`, or `legacy:typecheck` scripts when
working on them explicitly. `legacy:dev` covers the five packages with a real
`dev` script; the archived CLI uses `legacy:dev:cli`. They are not the
foundation for new product work.

- `cli/`: the archived npm CLI compatibility package
- `local/`: the archived local React server and UI bundled by that CLI
- `host-cloudflare/`: the archived self-hosted Cloudflare Worker
- `host-selfhost/`: the archived TypeScript self-hosted server and container
- `cloud/`: the previous managed Cloudflare deployment
- `desktop/`: the previous Electron desktop deployment

The shared TypeScript packages under `packages/` remain outside this directory.
They are retained independently from these deployment entry points.

Cloudflare previews and TypeScript package publishing remain manual or
repository-variable-gated compatibility workflows. They do not participate in
the native product release path.
