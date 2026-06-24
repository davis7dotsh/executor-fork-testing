# Legacy products

This directory contains the previous hosted cloud and Electron desktop product
entry points. The active product is the local/self-hosted Rust server and
Svelte dashboard in the repository root and `web/`.

The legacy packages remain in the Bun workspace so their dependency graph and
historical end-to-end scenarios stay reproducible. They are excluded from the
default development, test, typecheck, lint, format, and CI paths. Use the root
`legacy:dev`, `legacy:test`, or `legacy:typecheck` scripts when working on them
explicitly. They are not the foundation for new product work.

- `cloud/`: the previous managed Cloudflare deployment
- `desktop/`: the previous Electron desktop deployment

The shared TypeScript packages under `packages/` remain outside this directory.
They are retained independently from these deployment entry points.
