# Inbox note creation

## Summary

The OSS server now exposes `append_note` to an authenticated `kb:private`
connection when a writable inbox is configured. It creates exactly one new
Markdown file under the fixed logical path `99_inbox/`; it never accepts a path
or file name from the client and cannot modify existing documents.

This makes the same Inbox handoff available to ChatGPT and other OAuth MCP
clients: authorize `kb:private`, then ask the client to file a note or
conversation summary with `append_note`.

## Implementation

- `src/inbox.rs` owns the only writable surface. It validates title/body,
  generates a UTC name and YAML front matter, applies per-note and total-size
  limits, and uses `openat2` with `O_CREAT | O_EXCL` to prevent path escape or
  overwrite.
- `append_note` is registered in `src/server.rs` but is listed and callable
  only for the private scope and a usable inbox. Other scopes receive the same
  `tool not found` response as for an absent tool.
- `99_inbox/` remains outside `KB_PUBLIC_DIRS` and `KB_PRIVATE_DIRS`, so
  appended content cannot be discovered through `search` or read by `fetch`.
- Docker Compose mounts `${KB_HOST_PATH}/99_inbox` separately at `/inbox:rw`.
  `/kb` stays entirely read-only. Set `INBOX_CONTAINER_PATH=` to omit the write
  surface deliberately.

## Configuration

`INBOX_ROOT` is optional and must be an absolute path for local execution.
When it is unavailable, the server starts normally with only `search` and
`fetch`. Defaults are:

| Variable | Default |
| --- | --- |
| `INBOX_WRITES_PER_HOUR` | `10` |
| `INBOX_MAX_NOTE_BYTES` | `32768` |
| `INBOX_MAX_TOTAL_BYTES` | `8388608` |

## Remaining operational check

Before deploying, create the host `99_inbox/` directory and ensure it is
writable by the non-root container user. Reauthorize an existing ChatGPT
connector with `kb:private` if it was previously granted `kb:tech`; a token
with only the tech scope intentionally cannot see `append_note`.

Treat all Inbox content as untrusted because chat-originated notes can be
influenced by prompt injection. Review notes before moving them into the
canonical knowledge base.
