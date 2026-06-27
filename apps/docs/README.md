# Executor docs

The Executor documentation site, built with [Mintlify](https://mintlify.com).
This is a standalone Mintlify project (no `package.json`, so it is not part of
the bun workspace; Mintlify builds it in its own cloud).

## Develop

Run the Mintlify CLI directly. It needs an LTS Node (it rejects Node 25+):

```bash
bunx mint@latest dev            # http://localhost:3000
bunx mint@latest broken-links   # validate internal links
```

Edit the `.mdx` pages and the navigation in [`docs.json`](./docs.json); the dev
server hot-reloads.

## How it's served

Mintlify builds and hosts the site at `executor.mintlify.dev`. The canonical
public URL is `executor.sh/docs`, configured through the Mintlify project and
the production domain's external routing settings.

Mintlify is configured to host under the `/docs` subpath (Settings → Domain
setup → **Host at /docs**). The docs deployment is independent of archived code
under `legacy/`; no supported Executor runtime serves or proxies this site. A
Mintlify config change takes effect on the next docs build.

To deploy from this directory, point the Mintlify GitHub app at `apps/docs`.
