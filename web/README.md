# Executor web

The Svelte 5 and SvelteKit dashboard is a client-only SPA served from the Rust binary. It talks to
the Rust control API over the same origin. Release builds embed the generated static files, so the
installed binary has no Node.js runtime dependency.

## Local checks

Install workspace dependencies from the repository root with `bun install`. From this directory:

```sh
bun run format:check
bun run check
bun run typecheck
bun run lint
bun run test
```

The static adapter writes the production SPA to `web/build`. Build the web output before compiling
the release binary:

```sh
bun run --cwd web build
cargo build --release --locked
```

The Cargo build fails with an actionable error if the production assets are missing or malformed.
Normal checks and tests embed deterministic fixture assets instead, so they do not require a web
build. At runtime, the binary serves exact files with immutable caching and uses `index.html` only
for safe client-side navigation fallbacks.

The Rust server sends a deny-by-default Content Security Policy. The packaging step derives exact
SHA-256 hashes for every inline script in the generated HTML, so arbitrary inline scripts remain
blocked. Inline styles stay allowed for generated attributes. Audit that style allowance against
the first approved production web build and replace it with hashes or nonces where practical.

## First boot

Start the Rust server using the repository instructions. Open the `/setup#token=...` link printed
to the terminal. The dashboard removes the one-time token from browser history immediately, creates
the administrator, signs in, and opens `/sources`.

After setup, sign in at `/login`. Create gateway credentials under `/tokens`. Plaintext API tokens
are shown once and are never stored by the browser.
