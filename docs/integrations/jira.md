# Jira Integration Guide

Connect PushingTorPod EASM to Jira Cloud or Jira Data Center to automatically create and sync tickets for security findings.

## Prerequisites

- Jira Cloud or Jira Data Center instance
- API token (Cloud) or personal access token (Data Center)
- A Jira project dedicated to EASM findings
- PushingTorPod user with **admin** role in the tenant

## Setup

### Step 1: Create a Jira API Token

**Jira Cloud:**

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click **Create API token**
3. Give it a label like "EASM Integration"
4. Copy the token — you won't see it again

**Jira Data Center:**

1. Go to your profile → **Personal Access Tokens**
2. Click **Create token**
3. Set expiry (recommended: 1 year)
4. Copy the token

### Step 2: Create a Jira Project (if needed)

Create a dedicated project for EASM findings:

- **Project key**: `EASM` (or your choice)
- **Project type**: Kanban or Scrum
- **Issue type**: Bug or Task (will be used for all findings)

### Step 3: Configure in PushingTorPod

**Via UI:**

1. Navigate to **Settings → Integrations**
2. Select **Jira** as provider
3. Fill in the configuration:
   - **Jira URL**: `https://your-company.atlassian.net` (Cloud) or `https://jira.your-company.com` (Data Center)
   - **Email**: Your Jira account email
   - **API Token**: The token from Step 1
   - **Project Key**: `EASM`
   - **Issue Type**: `Bug` (or `Task`, `Story`, etc.)
4. Toggle options:
   - **Auto-create on triage**: Automatically creates a Jira ticket when a finding is triaged
   - **Sync status back**: Updates finding status when the Jira ticket is resolved
5. Click **Save**
6. Click **Test Connection** to verify

**Via API:**

```bash
curl -X POST "https://easm.securekt.com/api/v1/tenants/{tenant_id}/integrations/ticketing" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "jira",
    "config": {
      "url": "https://your-company.atlassian.net",
      "email": "security@your-company.com",
      "api_token": "ATATT3xFfGF0...",
      "project_key": "EASM",
      "issue_type": "Bug"
    },
    "auto_create_on_triage": false,
    "sync_status_back": true
  }'
```

### Step 4: Test the Connection

**Via UI:** Click the **Test Connection** button in the Integrations page.

**Via API:**

```bash
curl -X POST "https://easm.securekt.com/api/v1/tenants/{tenant_id}/integrations/ticketing/test" \
  -H "Authorization: Bearer $TOKEN"
```

Expected response:

```json
{
  "success": true,
  "message": "Successfully connected to Jira (project: EASM)",
  "provider": "jira"
}
```

## Usage

### Creating Tickets from Findings

**Via UI:**

1. Go to **Findings** or **Issues**
2. Click on a finding
3. Click **Create Ticket** button
4. A Jira ticket is created with finding details (severity, asset, evidence)

**Via API:**

```bash
curl -X POST "https://easm.securekt.com/api/v1/tenants/{tenant_id}/findings/{finding_id}/ticket" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider": "jira"}'
```

Response:

```json
{
  "id": 42,
  "finding_id": 99,
  "provider": "jira",
  "external_id": "EASM-123",
  "external_url": "https://your-company.atlassian.net/browse/EASM-123",
  "external_status": "To Do",
  "sync_status": "synced"
}
```

### Automatic Ticket Creation

When **auto_create_on_triage** is enabled:

- Every time a finding status changes to **TRIAGED**, a Jira ticket is automatically created
- The ticket includes: finding name, severity, affected asset, evidence, remediation guidance
- A link to the EASM finding is added to the Jira ticket description

### Bidirectional Sync

When **sync_status_back** is enabled:

- A background Celery task syncs ticket statuses every 30 minutes
- When a Jira ticket is moved to **Done/Resolved/Closed**, the EASM finding is updated to **FIXED**
- When a Jira ticket is reopened, the EASM finding is set back to **OPEN**

**Manual sync for a single finding:**

```bash
curl -X POST "https://easm.securekt.com/api/v1/tenants/{tenant_id}/findings/{finding_id}/ticket/sync" \
  -H "Authorization: Bearer $TOKEN"
```

**Full tenant sync:**

```bash
curl -X POST "https://easm.securekt.com/api/v1/tenants/{tenant_id}/tickets/sync" \
  -H "Authorization: Bearer $TOKEN"
```

## Jira Ticket Format

Created tickets include:

| Field           | Content                                                                   |
| --------------- | ------------------------------------------------------------------------- |
| **Summary**     | `[{SEVERITY}] {finding_name} — {asset_identifier}`                        |
| **Description** | Finding details, evidence, remediation, link to EASM                      |
| **Priority**    | Mapped from severity: Critical→Highest, High→High, Medium→Medium, Low→Low |
| **Labels**      | `easm`, `security`, `{severity}`                                          |
| **Issue Type**  | As configured (default: Bug)                                              |

## API Reference

| Method   | Endpoint                       | Description                             |
| -------- | ------------------------------ | --------------------------------------- |
| `POST`   | `/integrations/ticketing`      | Create/update Jira config               |
| `GET`    | `/integrations/ticketing`      | Get current config (credentials masked) |
| `DELETE` | `/integrations/ticketing`      | Deactivate integration                  |
| `POST`   | `/integrations/ticketing/test` | Test connection                         |
| `POST`   | `/findings/{id}/ticket`        | Create ticket for a finding             |
| `GET`    | `/findings/{id}/ticket`        | Get linked ticket info                  |
| `POST`   | `/findings/{id}/ticket/sync`   | Sync single ticket                      |
| `POST`   | `/tickets/sync`                | Sync all tenant tickets                 |

All endpoints are prefixed with `/api/v1/tenants/{tenant_id}`.

## Security Notes

- API tokens are **encrypted at rest** using AES-256 before storage
- Credentials are **never returned in API responses** — only masked versions (e.g., `AT**...Ff`)
- Only users with **admin** role can configure integrations
- The integration uses Jira REST API v3 (Cloud) or v2 (Data Center)
- All communication with Jira is over HTTPS

## Troubleshooting

| Problem                | Solution                                                                 |
| ---------------------- | ------------------------------------------------------------------------ |
| "Connection refused"   | Verify the Jira URL is correct and accessible from the EASM server       |
| "401 Unauthorized"     | Check email + API token. For Cloud, use email (not username)             |
| "403 Forbidden"        | Ensure the API token user has permission to create issues in the project |
| "Project not found"    | Verify the project key matches exactly (case-sensitive)                  |
| "Issue type not found" | Check available issue types in the project settings                      |
| Tickets not syncing    | Check that `sync_status_back` is enabled and Celery Beat is running      |
