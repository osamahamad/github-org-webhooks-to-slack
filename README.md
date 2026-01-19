# GitHub Org Webhooks to Slack (Cloudflare Worker)

A small Cloudflare Worker that receives GitHub Organization webhooks, validates the delivery signature (`X-Hub-Signature-256`), applies noise controls, and forwards security-focused notifications to a Slack channel using an Incoming Webhook.

## Why this exists

GitHub webhooks are powerful, but Slack channels get noisy fast. This Worker lets you:

- Receive only the org events you care about
- Verify requests are actually from GitHub (HMAC SHA-256 signature)
- Mute specific events, event actions, or repositories without changing your GitHub webhook
- Post formatted messages to Slack with bold titles, links, and delivery IDs

GitHub recommends validating webhook signatures before processing deliveries.

## Features

- Signature validation using `X-Hub-Signature-256` (HMAC SHA-256 over raw request body)
- Slack Incoming Webhook delivery (`{"text":"..."}`)
- Noise controls:
  - `MUTED_EVENTS`
  - `MUTED_EVENT_ACTIONS`
  - `MUTED_REPOS`
- Optional inclusion of `X-GitHub-Delivery` in Slack messages
- Embedded help link to inspect raw webhook payloads in GitHub “Recent deliveries”

## Supported GitHub events

This project is designed to work with the following event names (set in `CONFIG.ALLOWED_EVENTS`):

- `branch_protection_configuration`
- `branch_protection_rule`
- `repository_ruleset`
- `code_scanning_alert`
- `member`
- `delete`
- `custom_property_values`
- `deploy_key`
- `deployment`
- `deployment_status`
- `fork`
- `org_block`
- `organization`
- `personal_access_token_request`
- `pull_request`
- `repository`
- `repository_import`
- `repository_vulnerability_alert`
- `secret_scanning_alert_location`
- `secret_scanning_alert`
- `security_and_analysis`
- `team_add`
- `public`
- `gollum` (Wiki)
- `team`
- `release`
- `page_build`
- `milestone`
- `meta`

Official event reference: https://docs.github.com/en/webhooks/webhook-events-and-payloads

## Architecture

GitHub Org Webhook (HTTPS POST)  
→ Cloudflare Worker (validate signature, filter, format)  
→ Slack Incoming Webhook (message in channel)

## Requirements

- Cloudflare account with Workers enabled
- GitHub organization admin access (to create org-level webhook)
- Slack channel with an Incoming Webhook URL

## Setup

### 1) Create a Slack Incoming Webhook

Create an Incoming Webhook in Slack and copy the webhook URL. Store it in Cloudflare as a secret env var.

### 2) Deploy the Worker

You can deploy via the Cloudflare dashboard (UI) or Wrangler CLI.

#### Option A: Deploy via Cloudflare dashboard (UI)

1. Cloudflare Dashboard → Workers and Pages → Create application → Worker
2. Paste the Worker code
3. Deploy

#### Option B: Deploy via Wrangler CLI

1. Deploy your Worker
2. Set secrets (see below)

### 3) Configure Worker environment variables

Cloudflare Dashboard → Worker → Settings → Variables and Secrets

#### Required (Secrets)

- `SLACK_WEBHOOK_URL`  
  Your Slack Incoming Webhook URL

- `GITHUB_WEBHOOK_SECRET`  
  The shared secret used for GitHub webhook signature validation

Do not commit secrets to git. Prefer Cloudflare Secrets / Wrangler secret commands.

#### Optional (Text)

- `MUTED_EVENTS`  
- `MUTED_EVENT_ACTIONS`  
- `MUTED_REPOS`  
- `SHOW_DELIVERY_ID` (`true` or `false`, default is `true` if not set)

## Configure the GitHub Organization webhook

1. GitHub Org → Settings → Webhooks → Add webhook
2. Set:
   - Payload URL: your Worker URL
   - Content type: `application/json`
   - Secret: same exact value as `GITHUB_WEBHOOK_SECRET`
   - Enable SSL verification
   - Select “Let me select individual events”
   - Select only the events you want (match your `ALLOWED_EVENTS` list)

GitHub computes `X-Hub-Signature-256` as HMAC-SHA256 over the request body using the shared secret. Your Worker verifies this before processing.

## Testing

### Test using GitHub “Recent deliveries” (recommended)

GitHub lets you view deliveries, see headers and payload, and redeliver:
https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/viewing-webhook-deliveries

### Troubleshooting with logs

If your Worker returns non-200 responses, GitHub shows the response in the deliveries UI.

## Message formatting in Slack

This Worker sends a simple Slack Incoming Webhook payload:

- `{"text": "..."}`

Slack supports formatting like bold (`*text*`), emojis (`:shield:`), and links (`<url|label>`) in message text.

## Common issues

### 1) `401 Invalid signature`

Causes:
- GitHub webhook secret does not match `GITHUB_WEBHOOK_SECRET`
- Signature computed over different bytes (must be raw request body)

### 2) Slack message not arriving

Causes:
- `SLACK_WEBHOOK_URL` is wrong or not set as a secret
- Slack webhook disabled or rotated

### 3) Too much noise

Use the built-in muting controls to suppress noisy deliveries **without changing** your GitHub org webhook event selection.

These are **optional environment variables** (Text, comma-separated). Cloudflare documents environment variables (Text/JSON) and explains that secrets are also environment variables, but their values are hidden after set:
- https://developers.cloudflare.com/workers/configuration/environment-variables/
- https://developers.cloudflare.com/workers/configuration/secrets/

#### `MUTED_EVENTS`
Mute entire event types by name.

**Format:** `event,event,event`  
**Example:**
```text
MUTED_EVENTS = gollum,page_build,meta
```

If `X-GitHub-Event` matches one of these names, the Worker ignores the delivery.

#### `MUTED_EVENT_ACTIONS`
Mute specific actions for an event (example: allow PR opened/closed, mute PR edited).

**Format:** `event:action,event:action`  
**Example:**
```text
MUTED_EVENT_ACTIONS = pull_request:edited,repository:edited,team:edited
```

Notes:
- Many GitHub webhook payloads include an `action` field that changes what the event means.
- This Worker lowercases `payload.action`, so keep actions in lowercase.

#### `MUTED_REPOS`
Mute all deliveries for specific repositories, or repo prefixes.

**Format:** `org/repo,org/prefix-*`  
Supported patterns in this Worker:
- Exact match: `COMPANYNAME/repo`
- Trailing wildcard prefix: `COMPANYNAME/legacy-*`

**Example:**
```text
MUTED_REPOS = COMPANYNAME/playground,COMPANYNAME/legacy-*,COMPANYNAME/experiments-*
```

#### How to set these in Cloudflare

**Option A: Cloudflare Dashboard (UI)**
1. Cloudflare Dashboard → Workers & Pages
2. Select your Worker
3. Settings → Variables and Secrets
4. Add each variable as **Text**:
   - `MUTED_EVENTS`
   - `MUTED_EVENT_ACTIONS`
   - `MUTED_REPOS`
5. Deploy to apply changes

**Option B: Wrangler**
Add them under `vars` in your Wrangler config.

Example (`wrangler.jsonc`):
```jsonc
{
  "vars": {
    "MUTED_EVENTS": "gollum,page_build,meta",
    "MUTED_EVENT_ACTIONS": "pull_request:edited,repository:edited",
    "MUTED_REPOS": "COMPANYNAME/playground,COMPANYNAME/legacy-*",
    "SHOW_DELIVERY_ID": "true"
  }
}
```

Important: do not store sensitive values in `vars`. Use secrets for sensitive information.

## Security notes

- Do not commit secrets to your repo
- Rotate the GitHub webhook secret if it is ever exposed
- Keep Slack webhook URLs in Cloudflare secrets
- Always validate `X-Hub-Signature-256` before processing deliveries

## Contributing

PRs are welcome:
- Add better per-event formatting
- Add optional Slack Blocks formatting
- Add rate limiting and retries
- Add allowlists for org/repo names (defense in depth)

## License

Choose a license for open source, for example MIT.
