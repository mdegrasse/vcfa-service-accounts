# vcfa-service-accounts

Creates VCF Automation service accounts and gets their refresh tokens without using the GUI.
Works for the provider org and for tenant orgs. Python 3.10+, standard library only.

## Setup

The `.env` file is optional. Every setting can be given on the command line instead:

```sh
./vcfa_sa.py list --host vcfa.yourdomain.com --admin-token YOUR_TOKEN
```

To keep the settings in a file, copy the template and fill it in:

```sh
cp .env.example .env   # set VCFA_HOST and the admin credential
```

`--host` overrides `VCFA_HOST`. `.env` is git-ignored. The script does not store tokens: refresh tokens are printed to stdout.

## Admin credential

Commands that call the API need an admin credential. Use one of these:

- **`VCFA_ADMIN_REFRESH_TOKEN`** in `.env`, or **`--admin-token`** on the command line. The value
  can be an API refresh token (My Account > API Tokens), which is exchanged for a bearer token on
  each run, or a bearer JWT (starts with `eyJ`), which is used as-is. A JWT expires after about an
  hour, and the script stops with a clear message once it has passed.
- **`--admin-user`** (or `VCFA_ADMIN_USER`) logs in as an admin user, such as `admin@System`. The password comes from
  `VCFA_PASSWORD` if set, otherwise a hidden prompt. It is never printed or put on the command line.
  The script uses `/cloudapi/1.0.0/sessions` (tenant) or `/sessions/provider` (provider).

`--admin-user` and an admin token can't be used together. The credential must belong to the org being
targeted.

## Choosing the org

Without `--org`, the provider org is used. `--org NAME` targets a tenant org.

```sh
./vcfa_sa.py create --name my-svc                     # provider org
./vcfa_sa.py create --org planets --name my-svc       # tenant org
```

## Usage

`create` registers the account, turns Require Rotation off, approves the request through the API,
and prints the client ID and refresh token. Nothing is saved to disk, so copy the token to wherever
your automation keeps secrets. The output contains a live credential, so be careful where it goes
(shell history, logs, screen sharing).

```sh
./vcfa_sa.py create --name my-svc                                  # provider org, token from .env
./vcfa_sa.py create --name my-svc --admin-token YOUR_TOKEN         # provider org, token on the command line
./vcfa_sa.py create --name my-svc --admin-user admin@System        # provider org, logs in (prompts for password)
./vcfa_sa.py create --org planets --name my-svc --admin-token YOUR_TOKEN
./vcfa_sa.py create --org planets --name my-svc --admin-user admin@Planets
```

Every account gets a role. By default that is System Administrator in the provider org and
Organization Administrator in a tenant org. Use `--scope` to choose another role, given by name.
Pick the least privilege the account needs.

```sh
./vcfa_sa.py create --org planets --name my-svc --scope "Organization Master Owner"
./vcfa_sa.py create --name my-svc --scope "System Administrator"
```

## Examples

### Admin credentials

```sh
# Log in as a user. The password is prompted for, or read from VCFA_PASSWORD.
./vcfa_sa.py list --admin-user admin@System
./vcfa_sa.py list --org planets --admin-user admin@Planets

# Pass a token for one command, without a .env file.
./vcfa_sa.py list --host vcfa.yourdomain.com --admin-token YOUR_TOKEN

# Set the password in the environment for a single command, without prompting.
VCFA_PASSWORD='...' ./vcfa_sa.py list --admin-user admin@System
```

`--admin-user` and `--admin-token` can't be used together.

### Listing and inspecting

```sh
./vcfa_sa.py list                                  # provider org
./vcfa_sa.py list --org planets                    # tenant org
./vcfa_sa.py whoami --admin-user admin@System      # which user and roles the credential has
```

`list` shows the accounts the credential can see. A service account token only sees the accounts it
created, so use a user credential to see everything.

### Deleting

```sh
./vcfa_sa.py delete --name my-svc                  # asks you to type "yes"
./vcfa_sa.py delete --name my-svc --yes            # no prompt
./vcfa_sa.py delete --id urn:vcloud:serviceAccount:<uuid> --yes
./vcfa_sa.py delete --org planets --name my-svc --admin-user admin@Planets
```

Deletion may return 202, which means the server is processing it. Run `list` to confirm.

### Certificates and hosts

`--host` sets the VCF Automation host for one command. It overrides `VCFA_HOST`, so you can work
with a second environment without editing `.env`.

```sh
./vcfa_sa.py list --host vcfa.yourdomain.com --admin-user admin@System             # host from the command line
./vcfa_sa.py create --host vcfa-lab.yourdomain.com --name my-svc --admin-token YOUR_TOKEN
./vcfa_sa.py create --host vcfa-lab.yourdomain.com --org planets --name my-svc --admin-user admin@Planets
```

Without `--host`, the value of `VCFA_HOST` from `.env` or the environment is used.

TLS options:

```sh
./vcfa_sa.py list --ca-file /path/to/vcfa-ca.pem                # trust your private CA (preferred)
./vcfa_sa.py list --insecure                                    # skip verification (prints a warning)
./vcfa_sa.py create --host vcfa.yourdomain.com --ca-file ca.pem --name my-svc --admin-token YOUR_TOKEN
```

## Notes

- Require Rotation is always turned off, so the refresh token stays valid.
- The script does not store tokens. Refresh tokens are printed to stdout only.

## Self-signed certificates

Every command accepts TLS options:

```sh
./vcfa_sa.py list --ca-file /path/to/vcfa-ca.pem   # trust your private CA (preferred)
./vcfa_sa.py list --insecure                       # skip verification (prints a warning)
```

Use `--ca-file` with the CA that signed the VCFA certificate. Certificate checking stays on.
`--insecure` disables checking entirely, so use it only for a lab. The two flags can't be combined.

## Permissions

The admin user needs the Service Account View right to list and create, and the Service Account
Manage right to approve requests. `create` checks View access before it registers anything, so a
missing right can't leave an orphaned account behind. If a 403 happens later, the error names both
rights.

A service account session can only see and manage itself and the accounts it created. Use a user
credential for create, list, and delete.

## Endpoints

| Step | Request | Source |
|---|---|---|
| Register | `POST /oauth/{tenant/<org>\|provider}/register`, JSON with `software_id` | Org management and provider docs |
| Device code | `POST /oauth/{tenant/<org>\|provider}/device_authorization` | Org management docs |
| Lookup | `POST /cloudapi/1.0.0/deviceLookup`, JSON `{"userCode": ...}`, returns 303 with the account in `Location` | Broadcom API reference |
| Approve | `POST /cloudapi/1.0.0/deviceLookup/grant`, JSON `{"userCode": ...}`, 204 | Broadcom API reference |
| Refresh token | `POST /oauth/{tenant/<org>\|provider}/token`, device-code grant | Org management docs |
| Admin bearer | `POST /oauth/{tenant/<org>\|provider}/token`, `grant_type=refresh_token` (admin token only) | Org management docs |
| List | `GET /cloudapi/1.0.0/serviceAccounts?page=N&pageSize=32` | Broadcom API reference |
| Read, update, delete | `GET`, `PUT`, `DELETE /cloudapi/1.0.0/serviceAccounts/{id}` | Broadcom API reference |

Without an admin credential, `create` prints the user code and waits for you to approve it in the GUI.

## Unverified

These came from the docs but have not been run against a live instance:

- **Create body.** The provider register body follows the docs sample, with the scope encoded as
  `urn:vcloud:role:System%20Administrator`. The tenant role field is not documented. Use `--scope`
  for a different role.
- **Require Rotation.** Set through `PUT /cloudapi/1.0.0/serviceAccounts/{id}` with
  `requireRotation: false` and `tokenRotation: NEVER`. The script reads the full object, changes
  only these two fields, and PUTs it back.
- **Revoke.** `POST .../serviceAccounts/{id}/revoke` exists in the reference but isn't wrapped yet.
- **Delete and tokens.** The docs don't say whether deleting an account also revokes its tokens.
