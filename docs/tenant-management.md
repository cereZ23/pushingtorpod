# Tenant & user management

How multi-tenant access works in the platform: who logs in as what, which roles
can do what, and how a platform operator administers customer workspaces.

## Mental model

Three levels:

1. **Superuser** — the platform operator (e.g. `admin@easm.io`). Not a member of
   any single tenant: sees **all** tenants and can act as admin in any of them.
   This is the MSP / you.
2. **Tenant** — a customer workspace (e.g. `cere`, `cereSRL`). Owns assets, scans,
   findings, reports.
3. **Users** — logins that belong to a tenant. Created either at onboarding (the
   tenant **owner**) or added later from the tenant's **Users** page.

> Creating a tenant via **"+ New tenant" / Onboard Customer** mints the
> **customer's** owner account (the email/password you type are *theirs*, not a
> second identity for you). You keep logging in as superuser; the owner is the
> customer's login.

## Roles & permissions

Role is per-tenant (a user can be `admin` in one tenant and `viewer` in another).

| Role | Write (findings, scans…) | Manage users / settings | Notes |
|------|:---:|:---:|-------|
| **owner** | ✅ | ✅ | Created at onboarding. Highest; **protected** — cannot be edited/removed from the UI. |
| **admin** | ✅ | ✅ | Full access within the tenant. |
| **analyst** | ✅ | ❌ | Read + write; **default** when creating/inviting a user. |
| **viewer** | ❌ | ❌ | Read-only. |
| ~~member~~ | ✅ | ❌ | Legacy: still honoured as write, no longer offered in the picker. |
| **superuser** | ✅ (any tenant) | ✅ (any tenant) | Platform-level; bypasses per-tenant checks. |

Frontend gates (`stores/auth.ts`): `canWrite` = analyst/admin/owner/member (or
superuser); `canAdmin` = admin/owner (or superuser). `canAdmin` gates the
admin-only nav items and `requiresAdmin` routes; superuser status gates the
`superuserOnly` nav items and `requiresSuperuser` routes.

## Flows

### Create a tenant (onboarding)
`POST /api/v1/onboarding/register` (public, rate-limited 3/hour/IP). Creates, in
one transaction: the **tenant**, the **owner** user + membership, the **seed
domains**, and triggers the initial scan pipeline. The password must meet the
strength policy (≥8 chars with upper, lower, digit, special). The owner account
is a **separate login** for the customer.

### Manage a tenant's users
`Settings → Users` operates on the **currently-selected tenant**
(`/api/v1/tenants/{tenant_id}/users`, requires `admin` on that tenant). Create
users, invite by email, change role, deactivate. A banner shows **which** tenant
is being managed.

### Cross-tenant administration (superuser)
`Configuration → Tenants` (`/admin/tenants`, superuser-only) lists **every**
tenant with its owner and active user/asset counts
(`GET /api/v1/tenants/overview`). **Manage** switches into the tenant and opens
its Users page; on that page a superuser also gets an **inline tenant switcher**
in the banner to jump between tenants without leaving the screen.

## Access-control implementation

- **Backend** — `verify_tenant_access` (`app/api/dependencies.py`) grants a
  superuser `role="admin"` for any tenant and otherwise checks the user's active
  membership + required permission; it also sets the tenant context for RLS.
  `require_tenant_permission("admin")` guards the per-tenant user endpoints.
  `GET /api/v1/tenants/overview` is superuser-gated and uses `allow_cross_tenant()`
  so the RLS-protected asset counts span all tenants.
- **Frontend** — nav items carry `adminOnly` (→ `canAdmin`) or `superuserOnly`
  (→ `is_superuser`); routes carry `requiresAdmin` / `requiresSuperuser` enforced
  in the router guard (`router/index.ts`). The active tenant is a single source of
  truth: `auth.currentTenantId` derives from the tenant store, so roles recompute
  on login and on every tenant switch.

## Key endpoints

| Endpoint | Who | Purpose |
|----------|-----|---------|
| `POST /api/v1/onboarding/register` | public | Create tenant + owner + seeds |
| `GET /api/v1/tenants` | any (superuser: all) | Tenants for the switcher |
| `GET /api/v1/tenants/overview` | superuser | Cross-tenant overview (owner + counts) |
| `GET/POST/PATCH/DELETE /api/v1/tenants/{id}/users` | tenant admin | Per-tenant user management |
| `GET/POST/DELETE /api/v1/tenants/{id}/invitations` | tenant admin | Email invitations |

## Validation — tests performed

Manual end-to-end run against production on **2026-07-31**, one session per role
(separate incognito windows):

| Role | Account | Checks | Result |
|------|---------|--------|:---:|
| **Superuser** | `admin@easm.io` | `Tenants` page lists all tenants with owner/counts; **Manage** switches in and opens Users; inline tenant switcher reloads the user list | ✅ |
| **Owner** (non-superuser) | `cere1@mail.com` (cereSRL) | `Users` nav present **immediately after login, no refresh** (the RBAC regression); `Tenants` nav **hidden**; Users banner is **static** (no switcher); direct `/admin/tenants` **rebounds** to dashboard | ✅ |
| **Analyst** | `cere2@mail.com` (cereSRL) | `Users`/`Tenants` nav **absent**; direct `/settings/users` **rebounds** to dashboard | ✅ |
| **Viewer** | — | Expected: same nav as analyst **plus** read-only (no Create/Delete). **Not executed** in this session | ⏳ |

Related fixes shipped alongside this work (2026-07): RBAC single-source-of-truth
(#56), onboarding validation 500 on non-serializable `ValueError` (#57),
onboarding RLS 500 on context-less `seeds` insert (#58), login 401 masked as
"No refresh token available" (#59), superuser Tenants page + clearer per-tenant
user management (#60).
