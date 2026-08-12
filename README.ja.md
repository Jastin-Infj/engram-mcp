# engram-mcp

[English](README.md)

`engram-mcp` は、ローカルの Markdown ナレッジベースを小さな
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) サーバーとして公開します。
公開するのは読み取りツール二つと、厳しく限定した書込みツール一つです。

- `search`: 呼出元のscopeで見える Markdown を検索します。
- `fetch`: 見える Markdown を相対IDで一件取得します。
- `append_note`: `99_inbox/` に新しいMarkdownを一件だけ作成します。書込み可能な
  inboxが設定されている場合に限り、`kb:private` のクライアントへだけ表示されます。

HTTPS reverse proxy または Cloudflare Tunnel の背後で自己ホストすることを想定しています。
OAuth 2.1 Authorization Code + PKCE を実装し、ChatGPT や Claude などの MCP クライアントに
サーバー秘密値を渡さず接続できます。

## scope モデル

OAuth scope は固定の二層です。

| Scope | 参照できる内容 | Inboxへの書込み |
| --- | --- | --- |
| `kb:tech` | `INDEX.md` と `KB_PUBLIC_DIRS` | 不可 |
| `kb:private` | `kb:tech` の内容と `KB_PRIVATE_DIRS` | inboxが使用可能な場合に`append_note` |

既定の構成は次のとおりです。

```dotenv
KB_PUBLIC_DIRS=10_tech,20_projects
KB_PRIVATE_DIRS=90_private
```

両環境変数には、カンマ区切りの非隠しトップレベルディレクトリ名を指定します。両集合は
重複できません。scope外の文書への要求は `not_found` として扱い、`search` もscope外の
ディレクトリを列挙しません。

## セキュリティモデル

- 唯一の書込みツール`append_note`はtitleとMarkdown本文だけを受け取り、パスや
  ファイル名を受け取りません。`99_inbox/` に新規ファイルを一件作るだけで、既存ファイルの
  編集・上書き・削除、inboxの検索・取得はできません。
- コンテナはnon-rootで動作し、root filesystemとKB bind mountはread-onlyです。inboxは
  `/kb`配下に書込み可能な穴を開けず、別の書込み可能mountとして扱います。
- Linuxでは`openat2`の`RESOLVE_BENEATH`、`RESOLVE_NO_SYMLINKS`、
  `RESOLVE_NO_MAGICLINKS`を使います。パストラバーサル、symlink、special file、
  非Markdown IDを拒否します。
- OAuthはAuthorization Code + PKCE S256、resource indicator、protected-resource metadata、
  authorization-server metadata、Dynamic Client Registration（DCR）を使います。
- access / refresh tokenはHMAC署名、audience、期限で検証します。refresh tokenは毎回rotationし、
  旧tokenの再利用を検出すると同じ認可family（そのfamilyのaccess tokenを含む）を失効させます。
- 永続化するOAuth状態は`oauth_state` named volume内の、HMAC導出済みactive refresh token ID、
  期限、revoke flagだけです。token平文とclient secretは保存しません。
- audit logには導出済みcredential fingerprintだけを記録し、API key、Bearer token、
  authorization code、文書query、noteのtitle／本文は記録しません。

## アーキテクチャ

```text
MCP client
  │ HTTPS + OAuth 2.1
  ▼
Cloudflare Tunnel または reverse proxy
  ▼
cloudflared（任意） ── internal Docker network ── engram-mcp
                                                     ├─ /kb（read-only Markdown）
                                                     ├─ /inbox（新規noteのみ）
                                                     └─ /state（refresh-family stateのみ）
```

OAuth authorization serverとprotected resource serverは一つのprocessに同居します。公開HTTP面は
`/mcp`、`/healthz`、OAuth discovery / authorization / token / dynamic-registration endpointだけです。
KB本文はMCP tool resultからのみ返します。

## セットアップ

### 1. KBを用意する

`INDEX.md` と、設定したトップレベルディレクトリを含むディレクトリを用意します。既定構成では
`10_tech/`、`20_projects/`、`90_private/` です。設定済みディレクトリ内のMarkdownだけが
検索・取得対象になります。`kb:private`のクライアントからnoteを書き起こしたい場合は、別に
`99_inbox/`ディレクトリを作成します。inboxの内容は意図的に読取り対象外です。

### 2. 互いに異なる秘密値を生成する

ローカルで新しい値を生成してください。出力をissue、チャット、shell historyのexport、Gitへ
貼り付けないでください。

```bash
openssl rand -hex 32 # KB_KEY_A
openssl rand -hex 32 # KB_KEY_B
openssl rand -hex 32 # OAUTH_OWNER_SECRET
openssl rand -hex 48 # OAUTH_SIGNING_KEY
```

すべて異なる値を使用します。`KB_KEY_A` は `kb:tech`、`KB_KEY_B` は `kb:private` の
ローカル/API-key互換経路です。リモートMCPクライアントにはOAuthを使わせ、API keyを渡さないでください。

### 3. 設定する

```bash
cp .env.example .env
```

`.env` は自分で編集します。少なくともダミーの秘密値をすべて置き換え、次を設定します。

- `KB_HOST_PATH`: Markdown KBのホスト側ディレクトリ。
- `OAUTH_ISSUER`: 末尾`/`なしの公開HTTPS origin。
- `OAUTH_RESOURCE`: canonical MCP URL。通常は`https://kb.example.com/mcp`です。
- `MCP_ALLOWED_HOSTS`: 公開hostnameと`engram-mcp:8080`。
- `KB_PUBLIC_DIRS` / `KB_PRIVATE_DIRS`: 既定のKBレイアウトと異なる場合のみ変更します。
- `INBOX_ROOT`: `cargo run`時に使う、既存の`99_inbox`への絶対パス。Composeでは
  `${KB_HOST_PATH}/99_inbox`が存在し、コンテナユーザーから書込み可能であることを確認します。
  Composeはこれを`/kb`とは別に`/inbox`へmountします。

ローカルの`cargo run`では、`KB_ROOT`と絶対パスの書込み可能な`OAUTH_STATE_DIR`も設定します。
Docker Composeは`KB_ROOT=/kb`、`INBOX_ROOT=/inbox`、`OAUTH_STATE_DIR=/state`を自動設定します。
Composeで書込み機能を止めるには、`.env`の`INBOX_CONTAINER_PATH=`を空にします。読み取り機能には
影響しません。

### 4. 起動する

```bash
docker compose up -d --build
docker compose ps
```

既定のComposeはhost portを公開しません。internal Docker network上のreverse proxyまたはtunnelから
到達させる設計です。application dataを公開せずlivenessを確認するには、次を使います。

```bash
docker compose exec engram-mcp curl --fail --silent http://127.0.0.1:8080/healthz
```

## Cloudflare Tunnel の例

同梱の`cloudflared` serviceは`tunnel` profileでのみ起動します。

1. Cloudflare dashboardでremotely managed Tunnelを作成します。
2. `kb.example.com`のようなPublic Hostnameを`http://engram-mcp:8080`へ向けます。
3. 発行したtokenをローカル`.env`の`TUNNEL_TOKEN`に入れます。
4. profile付きで起動します。

   ```bash
   docker compose --profile tunnel up -d --build
   ```

5. 公開originから`/.well-known/oauth-protected-resource`に到達でき、認証なしの`/mcp`が
   Bearer challengeを返すことを確認します。

`cloudflared`だけが`edge` networkに接続します。MCPを到達可能にするためだけにhost portを
追加しないでください。

## MCP クライアントを接続する

接続前に`OAUTH_ISSUER`、`OAUTH_RESOURCE`、公開hostnameが同じHTTPS originであることを確認します。
このサーバーはDCR、PKCE S256、必要なOAuth grantをadvertiseします。

### ChatGPT

現在のChatGPTのconnector管理UIでcustom MCP serverを追加し、canonical MCP URL（例:
`https://kb.example.com/mcp`）を入力します。OAuth sign-inの案内に従って、必要なscopeだけを
承認します。会話の要約などを`append_note`でInboxへ書き起こしたい場合は`kb:private`を選び、
読み取り専用で使う場合は`kb:tech`を選びます。ChatGPTはprotected-resource / OAuth metadataを
discoveryし、必要に応じてDCRを実行して、PKCEを自動で完了します。

UI名や利用可否はaccountや更新で変わることがあります。表示されたredirect URIを確認し、
owner secretやsigning keyをChatGPTへ入力しないでください。詳細はOpenAI公式の
[authenticated MCP guide](https://developers.openai.com/plugins/build/auth)を参照してください。

### Claude

Claudeでcustom remote MCP connectorを追加し、同じcanonical URL
`https://kb.example.com/mcp`を指定してOAuth consentを完了します。追加のprivate directoryが
本当に必要な場合だけ`kb:private`を選び、それ以外は`kb:tech`にします。connectorがDCRを使う場合は
DCRを完了させ、server secretをclient ID / secret欄へコピーしないでください。

## Inboxへの書き起こし

`append_note`は追記専用です。成功すると
`99_inbox/2026-08-13-034500-project-summary.md`のようなID、作成時刻、保存byte数を返します。
ファイル名（UTC）とYAML front matter（`title`、`created`、`source`、秘密でないaudit fingerprint）は
サーバー側で生成します。Linuxではinboxを起点にした`openat2`と`O_CREAT | O_EXCL`で作成するため、
既存ファイルを開いて書き換えることはありません。

- 既定では本文は32 KiB、inbox直下の合計は8 MiB、書込みはサーバー全体で毎時10回までです。
  `INBOX_MAX_NOTE_BYTES`、`INBOX_MAX_TOTAL_BYTES`、`INBOX_WRITES_PER_HOUR`で変更できます。
- inboxが未設定・未mount・read-onlyなどで使用不能な場合、サーバーは`search`と`fetch`を継続し、
  `append_note`だけを表示しません。
- `99_inbox/`は未検証の入力として扱ってください。チャットはprompt injectionの影響を受けうるため、
  サーバー経由で正本KBを変更できない場合でも、内容を確認してから整理・移動してください。

設定と検証の詳細は[実装引き継ぎ](docs/features/inbox/implementation.md)および
[テスト計画](docs/features/inbox/test_plan.md)を参照してください。

## tokenの失効と再認可

- access tokenの既定は15分、refresh tokenの既定は14日です。refresh tokenは交換のたびに置換されます。
- 古いrefresh tokenが再利用されると、serverは拒否し、その認可familyを失効させます。そのclientで
  OAuth認可をやり直してください。
- すべてのaccess token、refresh token、署名済みDCR client IDを無効にするには、
  `OAUTH_SIGNING_KEY`を新規生成してapplication serviceを再作成します。signing key漏洩が
  疑われる場合の緊急対応です。
- 通常のkey rotationで`oauth_state` volumeを手動削除する必要はありません。token平文は入っておらず、
  新しいsigning keyが旧署名credentialを検証不能にするためです。

in-flight authorization codeは意図的にmemory-onlyで、server restart時に失われます。一方で
`OAUTH_SIGNING_KEY`と`oauth_state` volumeを保つ通常再起動では、有効な署名済みaccess tokenと
active refresh tokenを継続できます。

## 開発

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
docker compose --env-file .env.example config
docker compose --env-file .env.example build engram-mcp
```

GitHub Actionsはformat、warningsをerrorにしたClippy、Rust test suite全体を実行します。

## License

MITです。詳細は[LICENSE](LICENSE)を参照してください。
