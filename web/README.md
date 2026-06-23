# Executor web

The Svelte 5 and SvelteKit dashboard is a client-only SPA intended to be served by the Rust binary.
It talks to the Rust control API over the same origin. Static asset embedding and Rust fallback
serving are a separate packaging boundary and are not wired yet.

## Local checks

Install workspace dependencies from the repository root with `bun install`. From this directory:

```sh
bun run format:check
bun run check
bun run typecheck
bun run lint
bun run test
```

The static adapter is configured to write the production SPA to `web/build`. The future Rust
packaging step will embed that directory and serve `index.html` as the SPA fallback.

## First boot

Start the Rust server using the repository instructions. Open the `/setup#token=...` link printed
to the terminal. The dashboard removes the one-time token from browser history immediately, creates
the administrator, signs in, and opens `/sources`.

After setup, sign in at `/login`. Create gateway credentials under `/tokens`. Plaintext API tokens
are shown once and are never stored by the browser.
