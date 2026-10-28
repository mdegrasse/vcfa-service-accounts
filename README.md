# vcfa-service-accounts

Creates VCF Automation tenant service accounts and gets their refresh tokens without
using the GUI. Python 3.10+, standard library only.

## Setup

```sh
cp .env.example .env   # set VCFA_HOST, VCFA_ORG, VCFA_ADMIN_REFRESH_TOKEN
```

`.env` and `tokens/` are git-ignored. Tokens are stored with mode 0600.

## Usage

```sh
./vcfa_sa.py create --name my-svc          # one step: register, rotation off, grant, print refresh token
./vcfa_sa.py token                         # prints a valid access token (refreshes as needed)
./vcfa_sa.py list                          # service accounts in the org
./vcfa_sa.py login --client-id <id>        # re-run the device flow for an existing account
./vcfa_sa.py status | refresh | logout
./vcfa_sa.py rotation --name my-svc --off  # or --on, or --id <urn>
```

`create` does everything in one run and prints the new account's client ID and refresh token.
The refresh token is also stored in `tokens/<org>_<client_id>.json`, so you don't need to copy it
from the terminal. It prints the secret to stdout, so be careful where that output goes (shell
history, logs, screen sharing). Require Rotation is turned off by default, so the refresh token
stays valid. Pass `--keep-rotation` to leave it on.

Use a token: `curl -H "Authorization: Bearer $(./vcfa_sa.py token)" https://$VCFA_HOST/...`

### Self-signed certificates

Every command accepts TLS options:

```sh
./vcfa_sa.py list --ca-file /path/to/vcfa-ca.pem   # trust your private CA (preferred)
./vcfa_sa.py list --insecure                       # skip verification (prints a warning)
```

Use `--ca-file` with the CA that signed the VCFA certificate. Certificate checking stays on.
`--insecure` disables checking entirely, so use it only for a lab or to confirm a TLS problem.
The two flags cannot be combined.

### Choosing the org

Every command takes `--org`. Without it, `VCFA_ORG` is used.

```sh
./vcfa_sa.py create --org other-org --name my-svc
./vcfa_sa.py login  --org other-org --client-id <client-id>
./vcfa_sa.py list   --org other-org
```

Credentials are scoped to their org so a token is never sent to the wrong one:

- `VCFA_CLIENT_ID` and `VCFA_ADMIN_REFRESH_TOKEN` apply only to the `VCFA_ORG` default.
- For any other org, pass `--client-id` and set `VCFA_ADMIN_REFRESH_TOKEN_<ORG>`, where `<ORG>`
  is the org name in uppercase with non-alphanumeric characters replaced by `_`
  (for example `VCFA_ADMIN_REFRESH_TOKEN_OTHER_ORG` for `other-org`).
- Tokens are stored per org and client: `tokens/<org>_<client_id>.json`.

## API calls

| Step | Request | Source |
|---|---|---|
| Create | `POST /oauth/tenant/{org}/register` (JSON body, `software_id`) | VCFA docs, provider-side register sample |
| Device code | `POST /oauth/tenant/{org}/device_authorization`, form `client_id` | Org management docs |
| Lookup | `POST /cloudapi/1.0.0/deviceLookup`, JSON `{"userCode": ...}`, returns 303 with the account in `Location` | Broadcom API reference |
| Approve | `POST /cloudapi/1.0.0/deviceLookup/grant`, JSON `{"userCode": ...}`, 204 | Broadcom API reference |
| Refresh token | `POST /oauth/tenant/{org}/token`, form `grant_type=urn:ietf:params:oauth:grant-type:device_code` | Org management docs |
| Access token | `POST /oauth/tenant/{org}/token`, form `grant_type=refresh_token` | Org management docs |
| List | `GET /cloudapi/1.0.0/serviceAccounts` | Broadcom API reference |

Without `VCFA_ADMIN_REFRESH_TOKEN`, `login` prints the user code and waits for you to approve
it in the GUI, which is the old manual step.

## Unverified

These came from the docs but have not been run against a live instance:

- **Create body.** The docs only show the provider-side register body. `--scope` is passed
  through as-is if you need it; the tenant role field is not documented.
- **Require Rotation.** Set through `PUT /cloudapi/1.0.0/serviceAccounts/{id}` with
  `requireRotation: false` and `tokenRotation: NEVER`. The `ServiceAccount` schema documents these
  fields, but they have not been checked against a live instance. The script reads the full
  object, changes only these two fields, and PUTs it back, because the docs don't say whether PUT
  is a partial update. If the server rejects that body, check the error for the read-only fields
  it doesn't accept.
- **Service account lookup.** The `ServiceAccount` schema has no client ID field. `create` finds
  the new account by the software ID it sent, and `rotation` finds one by name. Both fail if the
  match is not exactly one account.
- **Admin rights.** The grant call's required role is not documented. It probably needs an org
  admin.
- **Revoke and delete.** `POST .../serviceAccounts/{id}/revoke` and `DELETE .../serviceAccounts/{id}`
  exist in the reference but are not wrapped by this script yet.
