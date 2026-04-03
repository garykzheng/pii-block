# MCP Privacy Proxy

A transparent proxy that sits between MCP clients (like Claude) and backend MCP servers, automatically detecting and masking PII with deterministic surrogates. When a tool returns results containing names, emails, SSNs, or other personal data, they're replaced with realistic fake values. When the client calls a tool using those fake values, the real data is restored before reaching the backend.

## How it works

```
Client (Claude, etc.)
        │
        ▼
┌─────────────────────┐
│  MCP Privacy Proxy  │
│                     │
│  Tool call args:    │
│  "Kari Robinson" ──►│──► "John Smith" (real value restored)
│                     │
│  Tool results:      │
│  "John Smith" ◄────│◄── "John Smith" (masked to surrogate)
│  becomes            │
│  "Kari Robinson"    │
└─────────────────────┘
        │
        ▼
  Backend MCP Server
```

PII is detected using a multi-phase approach:

1. **Field-level rules** — structured JSON fields like `first_name`, `email` are masked based on their path
2. **Known-value pre-scan** — previously seen PII is caught even without surrounding context
3. **Presidio NLP** — Microsoft Presidio detects new PII using regex + ML models

Surrogates are deterministic: the same input always produces the same fake output, so the LLM can reason about relationships between values without seeing real data.

## Quick start

### Prerequisites

- Python 3.11+
- A backend MCP server to proxy

### Install

```bash
pip install -e .
python -m spacy download en_core_web_lg
```

### Option 1: Stdio mode (for `.mcp.json` integration)

**Wrap a local MCP server** by putting the proxy in front of it:

```json
{
  "mcpServers": {
    "playwright": {
      "type": "stdio",
      "command": "python",
      "args": ["proxy.py", "--", "npx", "@playwright/mcp@latest"]
    }
  }
}
```

**Connect to a remote MCP server with OAuth** (e.g. Pylon, Linear, Sentry):

```json
{
  "mcpServers": {
    "pylon": {
      "type": "stdio",
      "command": "python",
      "args": ["proxy.py", "--auth", "oauth", "--backend-url", "https://mcp.usepylon.com/"]
    }
  }
}
```

On first connect, a browser window opens for OAuth authentication. Tokens are saved to disk — subsequent starts connect instantly without re-auth.

**Servers that require a pre-registered OAuth client** (e.g. Slack) can pass the client ID and callback port via environment variables:

```json
{
  "mcpServers": {
    "slack": {
      "type": "stdio",
      "command": "python",
      "args": ["proxy.py", "--auth", "oauth", "--backend-url", "https://mcp.slack.com/mcp"],
      "env": {
        "OAUTH_CLIENT_ID": "your-workspace-client-id",
        "OAUTH_CALLBACK_PORT": "3118"
      }
    }
  }
}
```

Most MCP servers (Linear, Pylon, Sentry, Datadog) support dynamic client registration and need no extra config — just `--auth oauth` and `--backend-url`.

**Connect to a remote server without OAuth:**

```json
{
  "mcpServers": {
    "my-server": {
      "type": "stdio",
      "command": "python",
      "args": ["proxy.py", "--backend-url", "http://localhost:3000/mcp"]
    }
  }
}
```

### Option 2: HTTP mode (with dashboard)

```bash
python server.py
```

This starts:
- **Dashboard** at `http://localhost:8080` — monitor masking activity, manage servers, edit policy
- **MCP endpoint** at `http://localhost:8080/mcp` — point your MCP client here

Register backend servers via the dashboard UI or the CLI:

```bash
python manage.py servers add playwright "npx @playwright/mcp@latest"
python manage.py servers add my-api "http://localhost:3000/mcp"
```

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `FPE_KEY` | Built-in dev key | Hex-encoded 128/192/256-bit key for format-preserving encryption. **Set this in production.** |
| `CONFIG_PATH` | `default_policy.yaml` | Path to the policy YAML file |
| `MAPPING_STORE_PATH` | `~/Library/Application Support/mcp-privacy-proxy/mappings.json` | Path to the encrypted PII mapping store |
| `SERVERS_PATH` | `servers.yaml` | Path to the server registry file |
| `OAUTH_CLIENT_ID` | — | Pre-registered OAuth client ID (for servers without dynamic registration, e.g. Slack) |
| `OAUTH_CALLBACK_PORT` | Random | Fixed port for the OAuth callback server |
| `HOST` | `127.0.0.1` | Bind address (HTTP mode only) |
| `PORT` | `8080` | Listen port (HTTP mode only) |
| `DASHBOARD_URL` | `http://127.0.0.1:8080` | Dashboard URL for remote audit logging (stdio mode only) |

### Policy file

The policy file controls what PII is detected and how it's masked. Copy `default_policy.yaml` to `policy.local.yaml` to customize:

```yaml
entities:
  PERSON:
    operator: deterministic_faker    # realistic fake names
  EMAIL_ADDRESS:
    operator: deterministic_faker    # realistic fake emails
  PHONE_NUMBER:
    operator: fpe                    # format-preserving encryption (keeps NNN-NNN-NNNN shape)
  US_SSN:
    operator: fpe
  CREDIT_CARD:
    operator: fpe
  LOCATION:
    operator: deterministic_faker
  DEFAULT:
    operator: replace
    new_value: '<REDACTED>'          # catch-all for unconfigured entity types

# Structured JSON field matching (glob syntax)
field_rules:
  - pattern: "*.first_name"
    entity: PERSON
  - pattern: "*.email"
    entity: EMAIL_ADDRESS
  - pattern: "*.ssn"
    entity: US_SSN

# Custom regex recognizers for domain-specific PII
custom_recognizers:
  - entity: EMPLOYEE_ID
    pattern: 'EMP\d{6}'
    score: 0.85
    operator: fpe

# Terms that should never be masked (company names, public domains, etc.)
allow_list:
  - "Acme Corp"
  - "public.example.com"
```

**Operators:**

| Operator | Behavior | Best for |
|---|---|---|
| `deterministic_faker` | HMAC-seeded Faker — same input always gives the same realistic fake value | Names, emails, addresses |
| `fpe` | Format-preserving encryption — output has the same format as input | SSNs, phone numbers, credit cards |
| `replace` | Static replacement string | Catch-all, or when you don't need reversibility |

### Mapping store

The proxy persists a bidirectional map of real values to surrogates so that:
- The same PII always maps to the same surrogate (deterministic)
- Surrogates can be reversed back to real values when needed (via dashboard or API)
- Multiple proxy instances can share the same mapping file

The mapping store is encrypted at rest with AES-256-GCM. The encryption key is stored in your OS keyring (macOS Keychain, etc.).

## Management CLI

```bash
# View overall status
python manage.py status

# Manage backend servers
python manage.py servers list
python manage.py servers add <name> <target>
python manage.py servers remove <name>
python manage.py servers enable <name>
python manage.py servers disable <name>

# View/edit policy
python manage.py policy show
python manage.py policy edit                          # opens in $EDITOR
python manage.py policy set-operator PERSON fpe       # change an operator

# Inspect mappings
python manage.py mappings show            # surrogates only
python manage.py mappings show --reveal   # shows real values
python manage.py mappings clear
```

## Dashboard

When running in HTTP mode (`python server.py`), the dashboard provides:

- **Live stats** — masking/de-mapping event counts, entity type breakdown
- **Audit log** — chronological record of all PII transformations
- **Server management** — add/remove/enable/disable backends, configure auth
- **Policy editor** — edit the masking policy with hot-reload (no restart needed)
- **De-mask API** — `POST /api/demask` to reverse surrogates back to real values

Stdio proxy instances automatically push audit events to the dashboard when it's running.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## How OAuth works

When `--auth oauth` is specified, the proxy handles the full OAuth lifecycle:

1. **First connection** — opens a browser for OAuth authorization, saves tokens to `~/Library/Application Support/mcp-privacy-proxy/oauth/`
2. **Subsequent connections** — loads saved tokens and preemptively refreshes them (handles short-lived tokens like Pylon's 5-minute TTL)
3. **Token refresh** — automatically refreshes expired access tokens using the stored refresh token
4. **De-mapping across servers** — the mapping store is shared across all proxy instances, so surrogates from one server (e.g. Pylon) are correctly de-mapped when passed to another (e.g. Slack)

## Limitations

- **Text only** — images, PDFs, and binary content pass through unmasked
- **User prompts are not masked** — only tool call arguments and tool results are intercepted
- **NLP detection has gaps** — uncommon name formats, domain-specific identifiers, and PII embedded in encoded data may not be caught. Add custom recognizers and field rules to cover your domain.
- **The default FPE key is for development only** — set `FPE_KEY` to a secure random key in production
