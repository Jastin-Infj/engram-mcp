# Inbox note creation test plan

## Acceptance checks

| Condition | Result | Evidence |
| --- | --- | --- |
| A private client can create a Markdown Inbox note | Passed | `tests/mcp_http.rs` writes a server-named file; `tests/oauth_http.rs` repeats it with a `kb:private` Bearer token. |
| A tech client cannot discover or invoke the write tool | Passed | `tech_scope_cannot_call_append_note_or_learn_that_it_exists`. |
| Existing KB files cannot be changed through the tool | Passed | `src/inbox.rs` accepts no path/file name and uses `O_CREAT | O_EXCL`; collision and symlink tests pass. |
| Inbox notes are not searchable or fetchable | Passed | `an_appended_note_stays_out_of_search_and_fetch`. |
| Unavailable Inbox does not take down read tools | Passed | `unavailable_inbox_costs_only_the_write_tool`. |

## Local validation — 2026-08-13

| Command | Result |
| --- | --- |
| `rtk cargo fmt --check` | Passed after formatting. |
| `rtk cargo clippy --all-targets -- -D warnings` | Passed, no issues. |
| `rtk cargo test --locked` | Passed, 69 tests across 5 suites. |
| `rtk docker compose --env-file .env.example config` | Passed; `/kb` is read-only and `/inbox` resolves as a separate bind mount. |
| `rtk docker compose --env-file .env.example build engram-mcp` | Passed; release image built successfully. |

No long GitHub Actions run was started or waited on. ROM/mGBA validation is not
applicable to this MCP server feature.

## Manual deployment check

1. Create a writable `${KB_HOST_PATH}/99_inbox` directory before starting
   Compose.
2. Reauthorize the ChatGPT connector with `kb:private`.
3. Ask it to save a short note to the Inbox and verify one new
   `YYYY-MM-DD-HHMMSS-<slug>.md` file appears.
4. Confirm the note cannot be returned by `search` or `fetch`.
