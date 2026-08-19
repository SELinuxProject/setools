# SETools MCP Server Configuration

The SETools MCP server reads its settings from an INI-format file parsed by
`setools.mcp.config.MCPConfig`. The file has a `[server]` section for the bind address, an
`[auth]` section selecting the authentication method, and one section per authentication method.
All sections are optional; the defaults are a loopback bind address with no authentication.

The server uses the HTTP transport when a configuration file is supplied and the stdio transport
when it is not, so the transport is not a setting in this file.

Start the server with an optional positional configuration path:

```console
setools-mcp [CONFIG]
```

For example, `setools-mcp docs/mcp-auth-jwt.ini` starts the HTTP server using that file. Running
`setools-mcp` without `CONFIG` starts the server over stdio without authentication.

## Server Settings

```ini
[server]
# Address to bind to.
host = 127.0.0.1

# Port to bind to.
port = 8000
```

Authentication only applies to the HTTP transport; the stdio transport inherits the security of
its local execution environment.

## Authentication Settings

The `[auth]` section selects the authentication method:

```ini
[auth]
method = jwt
```

The remaining sections are named after the method they configure. The option names match the
FastMCP provider constructor parameters, so the
[FastMCP authentication documentation](https://gofastmcp.com/servers/auth/authentication) is the
authoritative reference for their meaning.

| `method`         | FastMCP class                | Purpose                                          |
| ---------------- | ---------------------------- | ------------------------------------------------ |
| `none`           | (none)                       | Disable authentication.                          |
| `jwt`            | `JWTVerifier`                | Verify JWT bearer tokens.                        |
| `static`         | `StaticTokenVerifier`        | Verify hard-coded development tokens.            |
| `debug`          | `DebugTokenVerifier`         | Accept any non-empty token (development only).   |
| `introspection`  | `IntrospectionTokenVerifier` | Verify opaque tokens via RFC 7662 introspection. |
| `remote`         | `RemoteAuthProvider`         | Token verification plus OAuth discovery metadata for identity providers supporting dynamic client registration. |
| `oauth_proxy`    | `OAuthProxy`                 | Proxy an upstream OAuth provider that does not support dynamic client registration. |
| `oidc_proxy`     | `OIDCProxy`                  | Proxy an OpenID Connect provider using its discovery document. |

`OAuthProvider`, the full OAuth 2.0 authorization server implementation, is not configurable
through this file.

## Value Syntax

- Options documented as lists are comma-separated, for example `required_scopes = read, write`.
- `issuer` and `audience` accept either a single value or a comma-separated list.
- Boolean options accept the usual INI values: `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`.
- Parameters that cannot be expressed in a text file, such as the `DebugTokenVerifier` `validate`
  callable and the OAuth proxy `client_storage` backend, are not supported.

## Nested Token Verifiers

The `remote` and `oauth_proxy` methods wrap a token verifier. Set their `token_verifier` option to
one of `jwt`, `static`, `debug`, or `introspection` and configure the verifier in the section of
that name:

```ini
[auth]
method = remote

[remote]
token_verifier = jwt

[jwt]
jwks_uri = https://auth.example.com/.well-known/jwks.json
```

## Examples

- [mcp-auth-none.ini](mcp-auth-none.ini)
- [mcp-auth-jwt.ini](mcp-auth-jwt.ini)
- [mcp-auth-static.ini](mcp-auth-static.ini)
- [mcp-auth-debug.ini](mcp-auth-debug.ini)
- [mcp-auth-introspection.ini](mcp-auth-introspection.ini)
- [mcp-auth-remote.ini](mcp-auth-remote.ini)
- [mcp-auth-oauth-proxy.ini](mcp-auth-oauth-proxy.ini)
- [mcp-auth-oidc-proxy.ini](mcp-auth-oidc-proxy.ini)
