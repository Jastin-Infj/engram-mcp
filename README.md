# engram-mcp

[日本語版](README.ja.md)

`engram-mcp` exposes a local Markdown knowledge base as a small, read-only
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server. It
offers only two tools:

- `search` finds Markdown documents visible to the caller.
- `fetch` returns one visible Markdown document by its relative ID.

The server is designed for self-hosting behind an HTTPS reverse proxy or a
Cloudflare Tunnel. It implements OAuth 2.1 Authorization Code + PKCE and can
be used by MCP clients such as ChatGPT and Claude without giving those clients
your server secrets.

## Scope model

The fixed OAuth scopes are deliberately simple:

| Scope | Visible content |
| --- | --- |
| `kb:tech` | `INDEX.md` plus `KB_PUBLIC_DIRS` |
| `kb:private` | Everything visible to `kb:tech`, plus `KB_PRIVATE_DIRS` |

The defaults preserve the sample layout:

```dotenv
KB_PUBLIC_DIRS=10_tech,20_projects
KB_PRIVATE_DIRS=90_private
```

Both variables accept comma-separated, non-hidden top-level directory names.
They must not overlap. A request for a document outside the caller's scope is
handled as `not_found`; `search` does not enumerate out-of-scope directories.

## Security model

- There are no write tools, document HTTP endpoints, resources, or prompts.
- The container runs as a non-root user with a read-only root filesystem. The
  knowledge-base bind mount is read-only.
- On Linux, document reads use `openat2` with `RESOLVE_BENEATH`,
  `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`; traversal paths,
  symlinks, special files, and non-Markdown IDs are rejected.
- OAuth uses Authorization Code + PKCE S256, resource indicators, protected
  resource metadata, authorization-server metadata, and dynamic client
  registration (DCR).
- Access and refresh tokens are HMAC-signed, audience-bound, and expiry-bound.
  Refresh tokens rotate on every use. Reusing an old refresh token revokes its
  whole authorization family, including that family's access tokens.
- The only persistent OAuth data is an HMAC-derived active refresh-token ID,
  expiry, and revocation flag in the `oauth_state` named volume. Token plaintext
  and client secrets are not stored there.
- Access logs use derived credential fingerprints and never log API keys,
  bearer tokens, authorization codes, or document queries.

## Architecture

```text
MCP client
  │ HTTPS + OAuth 2.1
  ▼
Cloudflare Tunnel or reverse proxy
  ▼
cloudflared (optional) ── internal Docker network ── engram-mcp
                                                    ├─ /kb (read-only Markdown)
                                                    └─ /state (refresh-family state only)
```

The OAuth authorization server and protected resource server are one process.
The public HTTP surface consists of `/mcp`, `/healthz`, OAuth discovery,
authorization, token, and dynamic-registration endpoints. The knowledge-base
contents are returned only through MCP tool results.

## Quick start

### 1. Prepare a knowledge base

Create a directory with `INDEX.md` and the top-level directories you configured.
For the defaults, that means `10_tech/`, `20_projects/`, and `90_private/`.
Only Markdown files in those configured directories are searchable or fetchable.

### 2. Generate independent secrets

Generate new values locally. Do not paste their output into issue trackers,
chat, shell history exports, or Git.

```bash
openssl rand -hex 32 # KB_KEY_A
openssl rand -hex 32 # KB_KEY_B
openssl rand -hex 32 # OAUTH_OWNER_SECRET
openssl rand -hex 48 # OAUTH_SIGNING_KEY
```

Use a different value for every variable. `KB_KEY_A` maps to `kb:tech` and
`KB_KEY_B` maps to `kb:private` for local/API-key compatibility. Remote MCP
clients should use OAuth rather than sending either API key.

### 3. Configure the service

```bash
cp .env.example .env
```

Edit `.env` yourself. At minimum, replace all dummy secrets and set:

- `KB_HOST_PATH` to the directory containing your Markdown knowledge base.
- `OAUTH_ISSUER` to your public HTTPS origin, without a trailing slash.
- `OAUTH_RESOURCE` to the canonical public MCP URL, normally
  `https://kb.example.com/mcp`.
- `MCP_ALLOWED_HOSTS` to the public hostname and `engram-mcp:8080`.
- `KB_PUBLIC_DIRS` and `KB_PRIVATE_DIRS` if the default layout does not match
  your knowledge base.

For local `cargo run`, also set `KB_ROOT` and an absolute, writable
`OAUTH_STATE_DIR`. Docker Compose sets `KB_ROOT=/kb` and `OAUTH_STATE_DIR=/state`
for you.

### 4. Start the service

```bash
docker compose up -d --build
docker compose ps
```

The default Compose file does not publish a host port. It is intended to be
reached only by a reverse proxy or tunnel on the internal Docker network.

Check liveness without exposing application data:

```bash
docker compose exec engram-mcp curl --fail --silent http://127.0.0.1:8080/healthz
```

## Cloudflare Tunnel example

The bundled `cloudflared` service is opt-in through the `tunnel` profile.

1. Create a remotely managed Cloudflare Tunnel in the Cloudflare dashboard.
2. Configure a public hostname such as `kb.example.com` to route to
   `http://engram-mcp:8080`.
3. Put the generated tunnel token in your local `.env` as `TUNNEL_TOKEN`.
4. Start the profile:

   ```bash
   docker compose --profile tunnel up -d --build
   ```

5. Confirm from the public origin that
   `/.well-known/oauth-protected-resource` is reachable and an unauthenticated
   `/mcp` request returns a Bearer challenge.

`cloudflared` is the only service connected to the `edge` network. Do not add
host-port publishing merely to make the MCP server reachable.

## Connect an MCP client

Before connecting a client, confirm that `OAUTH_ISSUER`, `OAUTH_RESOURCE`, and
the public hostname all use the same HTTPS origin. The server advertises DCR,
PKCE S256, and the two OAuth grants required for the flow.

### ChatGPT

In the current ChatGPT connector-management UI, add a custom MCP server and
enter your canonical MCP URL, for example `https://kb.example.com/mcp`. Follow
the OAuth sign-in prompt and approve only the scope you intend to grant;
normally this is `kb:tech`. ChatGPT discovers the protected-resource and OAuth
metadata, may dynamically register a client, and completes PKCE automatically.

The exact UI and account availability can change. Verify the shown redirect URI
and use the server's consent page rather than supplying the owner secret or
signing key to ChatGPT. See the official
[authenticated MCP guide](https://developers.openai.com/plugins/build/auth).

### Claude

Create a custom remote MCP connector in Claude, provide the same canonical
`https://kb.example.com/mcp` URL, and finish the OAuth consent flow. Choose
`kb:private` only when that client genuinely needs the additional private
directories; otherwise select `kb:tech`. If the connector uses dynamic client
registration, let it complete DCR and do not copy server secrets into its
client-ID or client-secret fields.

## Token expiry and revocation

- Access tokens default to 15 minutes. Refresh tokens default to 14 days and
  are replaced every time they are exchanged.
- If an old refresh token is replayed, the server rejects it and revokes that
  authorization family. Complete OAuth authorization again for that client.
- To invalidate every access token, refresh token, and signed DCR client ID,
  generate a new `OAUTH_SIGNING_KEY` and recreate the application service. This
  is the emergency response for a suspected signing-key compromise.
- Do not manually delete the `oauth_state` volume during normal key rotation.
  It contains no token plaintext, and the new signing key already prevents old
  signed credentials from verifying.

An in-flight authorization code is intentionally memory-only and is lost on a
server restart. Valid signed access tokens and active refresh tokens survive a
normal restart when both `OAUTH_SIGNING_KEY` and the `oauth_state` volume are
preserved.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
docker compose --env-file .env.example config
docker compose --env-file .env.example build engram-mcp
```

The GitHub Actions workflow runs formatting, Clippy with warnings denied, and
the full Rust test suite.

## License

MIT. See [LICENSE](LICENSE).
