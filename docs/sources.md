# Sources, credentials, and managed OAuth

Source management is available only to the signed-in administrator. API tokens
can discover and call the resulting global catalog, but cannot create sources,
change credentials, or alter tool modes.

## Before connecting

Open **Sources** in the dashboard. Give each source a clear name and, when
offered, a stable preferred slug. Tool paths use
`tools.<source_slug>.<tool_name>`.

Outbound connections ignore ambient HTTP proxy variables and do not follow
tool-call redirects. Public targets are allowed by default. Enable **Allow
private network addresses** only when the source intentionally runs on
loopback or a private network. Link-local, cloud metadata, multicast, and
reserved targets remain blocked.

For a managed OAuth source, that same opt-in also covers issuer discovery, MCP
protected-resource discovery, authorization metadata, token exchange, and
refresh endpoints. It can permit loopback HTTP for those OAuth endpoints. Keep
the opt-in off unless both the source and its OAuth provider intentionally need
private-network reachability.

Credentials are encrypted with the instance master key and are never shown
again. Enter secrets in the dashboard, not in endpoint URLs. Static credentials
take precedence over a managed OAuth connection for the same credential key.

## OpenAPI

1. Choose **OpenAPI service**.
2. Select **URL** or **Paste**, then provide an OpenAPI 3.0 or 3.1 document in
   JSON or YAML.
3. Select **Preview specification** and review the detected operations and
   security schemes.
4. Enter any API key, bearer, basic, or manual OAuth access-token credentials.
5. Import the source, then review its effective tool modes under **Tools**.

Swagger 2 and external references are not supported. For a URL import, the
document's server information determines the upstream request target. Query
parameters in a source URL are treated as protected credential state and are
not shown in source metadata.

Managed OAuth becomes available after import for supported authorization-code
security schemes. Configure each eligible scheme separately in the source's
**Managed OAuth** panel.

## GraphQL

1. Choose **GraphQL API**.
2. Enter the GraphQL endpoint and source name.
3. Select static authentication when you intend to use it. For managed OAuth,
   choose **None**.
4. Connect the source and review its imported queries and mutations.

Introspection must succeed before tools can be imported and on later refreshes.
With no static credential, a recognized authentication-required response
stages an empty source so you can configure its managed OAuth `default`
credential, authorize it, and then refresh the catalog.
Queries start Enabled, mutations start Ask, and deprecated operations start
Disabled. Managed OAuth uses the GraphQL source's `default` credential.

## MCP Streamable HTTP

1. Choose **MCP Streamable HTTP**.
2. Enter the endpoint and source name.
3. Select no authentication, bearer, basic, API-key header, or a manually
   managed OAuth access token.
4. Connect, then review imported tools and their modes.

Executor currently requires MCP protocol version `2025-11-25`. It imports MCP
tools only. An upstream tool starts Enabled only when the upstream explicitly
marks it read-only without also marking it destructive. All other imported MCP
tools start Ask.

For managed OAuth, first create the HTTP MCP source without a static
credential, then configure its `default` credential in **Managed OAuth**. See
[MCP support](mcp.md) for transport limits and lifecycle details.

## MCP stdio templates

Dashboard users cannot submit arbitrary commands. A machine administrator must
approve the executable, arguments, working directory, static environment, and
names of secret environment fields in a JSON template file. Start Executor
with:

```sh
executor server \
  --mcp-stdio-templates /absolute/path/to/mcp-stdio-templates.json
```

The equivalent environment variable is
`EXECUTOR_MCP_STDIO_TEMPLATES_FILE`. The file format is:

```json
{
  "templates": [
    {
      "name": "filesystem",
      "executable": "/absolute/path/to/mcp-server",
      "cwd": "/absolute/path/to/approved-directory",
      "arguments": ["--stdio"],
      "environment": {
        "LOG_LEVEL": "warn"
      },
      "secretEnvironment": ["API_TOKEN"]
    }
  ]
}
```

Restart Executor after editing the registry. In **Sources**, choose **MCP local
template**, select the approved template, and enter every required secret. The
template allowlist is a command-selection control, not a sandbox between
Executor and the selected process. Every approved executable runs with
Executor's operating-system identity and must be fully trusted.

Protect the template file, executable, working directory, and every ancestor
path from untrusted writes. Executor canonicalizes and validates configured
targets when it loads the registry, but it does not enforce their ownership or
permissions.

The systemd and launchd installers create empty template registries at their
documented service paths. Docker mounts the repository's empty example by
default. Container templates must reference Linux executables available at the
same absolute path inside the container.

## Managed OAuth

Managed OAuth supports eligible OpenAPI authorization-code schemes, the
GraphQL `default` credential, and the HTTP MCP `default` credential. It uses
authorization-code flow with PKCE and stores access and refresh tokens
encrypted. This is OAuth 2 only. OpenID Connect and the `openid` scope are not
supported.

Before configuring OAuth, start Executor with the exact browser-facing origin:

```sh
executor server --public-origin https://executor.example.com
```

Or set:

```sh
EXECUTOR_PUBLIC_ORIGIN=https://executor.example.com
```

The value must be an origin only, with no path, query, fragment, or embedded
credentials. It controls control-mutation Origin checks, MCP Host and Origin
validation, cookie security, setup links, and OAuth callbacks. Keep Executor
bound to loopback and terminate TLS at a local reverse proxy.

Then:

1. Import the source.
2. Open its **Managed OAuth** panel.
3. Choose the eligible credential and enter the provider issuer, client ID,
   client authentication method, optional client secret, and requested scopes.
   For HTTP MCP, provider discovery can begin from the MCP protected resource.
4. Save the connection.
5. Copy the callback URL displayed by Executor and register that exact URL with
   the provider.
6. Select **Connect OAuth** and finish authorization in the provider window.
7. Return to the source and refresh its catalog if it was created before
   authorization completed.

Callback paths are connection-specific:

```text
/api/v1/oauth/callback/<connection-id>
```

Do not replace them with one shared callback path. If the provider revokes the
grant or refresh fails, the dashboard marks the connection for
reauthorization. Disconnecting removes active token material without deleting
the source.

## Tool modes and refresh

Each tool has an intrinsic mode, an optional source override, and an optional
tool override. Effective mode precedence is:

1. Tool override
2. Source override
3. Intrinsic mode

Enabled calls run immediately. Ask calls wait for the administrator under
**Approvals**. Disabled tools stay visible to the administrator but are hidden
from gateway search and cannot be invoked.

Use **Refresh** after an upstream OpenAPI document, GraphQL schema, or MCP tool
list changes. A failed refresh leaves the last successfully imported catalog
in place. Deleting and recreating a source intentionally discards its stable
tool identity and tombstone history.
