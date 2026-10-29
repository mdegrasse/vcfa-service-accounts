#!/usr/bin/env python3
"""Create and manage VCF Automation service accounts in the provider or a tenant org.

Automates the flow that was previously done by hand in the GUI and Bruno:

  create    register, turn Require Rotation off, approve via API, print refresh token
  list      list service accounts visible to the credential
  delete    delete a service account (asks for confirmation unless --yes)

One admin credential is used for create, list, and delete, and for the approval in create: an API
refresh token or a bearer JWT (My Account > API Tokens), set as VCFA_ADMIN_REFRESH_TOKEN in .env or
passed with --admin-token, or a --user login. Without one, create prints the user code for GUI approval.

Configuration (environment variables, or a local .env file):
  VCFA_HOST                 e.g. automation.example.com (no scheme)
  (no --org)                create or manage in the provider org (default)
  --org NAME                create or manage in a tenant org
  VCFA_ADMIN_REFRESH_TOKEN  admin API token (refresh token, or a bearer JWT) for the org you target
"""

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_GRANT = "refresh_token"
REQUEST_TIMEOUT = 30
ACCEPT = "application/json;version=40.0"
# Set by main() from --ca-file / --insecure. None means system trust store.
SSL_CONTEXT: ssl.SSLContext | None = None


def make_ssl_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext | None:
    """Trust a private CA (--ca-file) or skip verification (--insecure)."""
    if insecure:
        print("WARNING: --insecure disables TLS certificate verification.", file=sys.stderr)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_file:
        if not Path(ca_file).is_file():
            sys.exit(f"--ca-file not found: {ca_file}")
        return ssl.create_default_context(cafile=ca_file)
    return None


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing values."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def config(args: argparse.Namespace) -> dict:
    """Build the run configuration. Without --org the provider org is used.

    One admin credential is used for whichever org is targeted: --user, --admin-token,
    or VCFA_ADMIN_REFRESH_TOKEN from the environment or .env. It must belong to the org
    being targeted. Service accounts are referred to by name; their client ids are
    looked up by name when needed, so no client id is needed here.
    """
    load_dotenv(PROJECT_DIR / ".env")
    host = os.environ.get("VCFA_HOST", "").strip()
    org = (getattr(args, "org", None) or "").strip()
    is_provider = not org

    admin_refresh = (getattr(args, "admin_token", None) or os.environ.get("VCFA_ADMIN_REFRESH_TOKEN", "")).strip()
    user = (getattr(args, "user", None) or os.environ.get("VCFA_USER", "")).strip()
    if user and admin_refresh and getattr(args, "admin_token", None):
        sys.exit("Use either --user (with a password) or an admin token, not both.")

    name = (getattr(args, "name", None) or "").strip()
    cfg = {"host": host, "org": org, "name": name, "admin_refresh": admin_refresh, "user": user}
    if not host:
        sys.exit("Missing configuration: VCFA_HOST")
    if "://" in host:
        sys.exit("VCFA_HOST must be a bare host name, without https://")
    return cfg


def org_label(cfg: dict) -> str:
    return cfg["org"] or "provider"


def oauth_path(cfg: dict) -> str:
    """/oauth/provider for the provider org, /oauth/tenant/{org} for a tenant org."""
    return f"/oauth/tenant/{cfg['org']}" if cfg["org"] else "/oauth/provider"


def http(method: str, url: str, headers: dict, body: bytes | None = None) -> tuple[int, dict]:
    """Send a request. Returns (status, parsed JSON body or {}).

    Non-2xx responses are returned rather than raised: the device flow expects
    'authorization_pending' while polling, and callers decide what an error means.
    """
    req = urllib.request.Request(url, data=body, method=method, headers={"Accept": ACCEPT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach {url}: {exc.reason}")

    if not raw:
        return status, {}
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"error": "non_json_response", "error_description": raw[:300].decode(errors="replace")}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib following redirects so the Location header of a 303 is visible."""

    def redirect_request(self, *args, **kwargs):
        return None


def http_no_redirect(method: str, url: str, headers: dict, body: bytes | None = None) -> tuple[int, str | None, dict]:
    """Like http(), but returns (status, Location header, body) without following redirects."""
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=SSL_CONTEXT))
    req = urllib.request.Request(url, data=body, method=method, headers={"Accept": ACCEPT, **headers})
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            status, location, raw = resp.status, resp.headers.get("Location"), resp.read()
    except urllib.error.HTTPError as exc:
        status, location, raw = exc.code, exc.headers.get("Location"), exc.read()
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach {url}: {exc.reason}")
    return status, location, json.loads(raw) if raw else {}


def verify_pending_request(cfg: dict, bearer: str, user_code: str) -> None:
    """Look up the device request by user code and check it before granting.

    Mirrors the GUI's Lookup step. The lookup returns 303 with a Location for the
    service account. Only a request in REQUESTED state is granted.
    """
    status, location, payload = http_no_redirect(
        "POST", f"https://{cfg['host']}/cloudapi/1.0.0/deviceLookup",
        {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
        json.dumps({"userCode": user_code}).encode(),
    )
    if status == 404:
        sys.exit(f"No pending access request for user code {user_code}.")
    if status != 303 or not location:
        fail("Device lookup", status, payload)
    if location.startswith("/"):
        location = f"https://{cfg['host']}{location}"
    status, sa = http("GET", location, {"Authorization": f"Bearer {bearer}"})
    if status != 200:
        fail("Get pending service account", status, sa)
    if sa.get("status") != "REQUESTED":
        sys.exit(f"Service account '{sa.get('name')}' is {sa.get('status')}, not REQUESTED. Not granting.")
    print(f"Pending request from service account '{sa.get('name')}' verified.")


def post_form(url: str, fields: dict, bearer: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return http("POST", url, headers, urllib.parse.urlencode(fields).encode())


def api(cfg: dict, method: str, path: str, bearer: str, body: dict | None = None) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {bearer}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    return http(method, f"https://{cfg['host']}{path}", headers, data)


def oauth_url(cfg: dict, endpoint: str) -> str:
    return f"https://{cfg['host']}{oauth_path(cfg)}/{endpoint}"


def fail(what: str, status: int, payload: dict) -> None:
    detail = payload.get("error_description") or payload.get("message") or payload.get("error") or ""
    msg = f"{what} failed ({status}): {detail}".rstrip(": ").rstrip()
    if status == 403:
        msg += ("\nThe admin token's user needs the Service Account View right (list, create) and "
                "the Service Account Manage right (approve requests).")
    sys.exit(msg)


# --- admin credential -------------------------------------------------------

def is_jwt(token: str) -> bool:
    """Access tokens are JWTs (eyJ..., three dot-separated parts). API refresh tokens are not."""
    return token.startswith("eyJ") and token.count(".") == 2


def jwt_expiry(token: str) -> float | None:
    """Return the exp claim of a JWT without verifying it. None if absent or unreadable."""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp"))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def session_login(cfg: dict) -> str:
    """Log in with a username and password and return the session token.

    Uses POST /cloudapi/1.0.0/sessions (tenant) or /sessions/provider (provider) with basic
    auth. The session token comes back in the X-VMWARE-VCLOUD-ACCESS-TOKEN response header.
    The password is taken from VCFA_PASSWORD, or prompted for, and never printed.
    """
    password = os.environ.get("VCFA_PASSWORD") or getpass.getpass(f"Password for {cfg['user']}: ")
    cred = base64.b64encode(f"{cfg['user']}:{password}".encode()).decode()
    path = "/cloudapi/1.0.0/sessions" if cfg["org"] else "/cloudapi/1.0.0/sessions/provider"
    headers = {"Authorization": f"Basic {cred}", "Accept": "application/*;version=9.0.0"}
    req = urllib.request.Request(f"https://{cfg['host']}{path}", method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=SSL_CONTEXT) as resp:
            status, resp_headers, raw = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        status, resp_headers, raw = exc.code, exc.headers, exc.read()
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach {path}: {exc.reason}")
    token = resp_headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
    if status != 200 or not token:
        fail(f"Session login as {cfg['user']}", status, json.loads(raw) if raw[:1] == b"{" else {})
    return token


def admin_bearer(cfg: dict) -> str:
    """Return a bearer token for the admin calls.

    A JWT is used as-is, since it is already a bearer token. Anything else is treated as
    an API refresh token and exchanged for a short-lived bearer token.
    """
    if cfg.get("user"):
        return session_login(cfg)
    token = cfg["admin_refresh"]
    if not token:
        sys.exit("This command needs an admin token (VCFA_ADMIN_REFRESH_TOKEN or --admin-token) or a --user login.")
    if is_jwt(token):
        exp = jwt_expiry(token)
        if exp is not None and exp <= time.time():
            sys.exit(f"The bearer token expired at {time.ctime(exp)}. Get a new one or use a refresh token.")
        return token
    status, payload = post_form(oauth_url(cfg, "token"), {
        "grant_type": REFRESH_GRANT,
        "refresh_token": token,
    })
    if status != 200 or "access_token" not in payload:
        fail("Admin token exchange", status, payload)
    return payload["access_token"]


# --- token storage ----------------------------------------------------------

def token_response(payload: dict) -> dict:
    """Return the refresh token and access token from a token response. Nothing is stored."""
    if not payload.get("refresh_token"):
        sys.exit("Token response contained no refresh_token.")
    return {
        "refresh_token": payload["refresh_token"],
        "access_token": payload.get("access_token"),
        "expires_in": payload.get("expires_in"),
    }


# --- commands ---------------------------------------------------------------

def cmd_create(cfg: dict, args: argparse.Namespace) -> None:
    """Create a service account end to end and print its refresh token.

    Steps: register, turn Require Rotation off, device flow with API approval, print the
    refresh token. Nothing is stored locally. The register body follows the provider-side sample in the VCF Automation
    docs (software_id marks a service account). The tenant-side scope/role field is not
    documented, so it is passed through only if --scope is given. Verify on first use.
    """
    bearer = admin_bearer(cfg)
    # Check the token can read service accounts before registering anything. Otherwise a
    # missing right fails after the account exists, leaving an orphaned account behind.
    list_service_accounts(cfg, bearer)
    body = {
        "client_name": args.name,
        "software_id": args.software_id or str(uuid.uuid4()),
        "software_version": args.software_version,
        "client_uri": args.client_uri,
    }
    # Every account needs a role, or the GUI shows it blank. --scope takes a role name
    # (encoded here) or a full urn:vcloud:role URN. Defaults: System Administrator for the
    # provider, Organization Administrator for a tenant org.
    role = args.scope or ("System Administrator" if not cfg["org"] else "Organization Administrator")
    body["scope"] = role if role.startswith("urn:") else "urn:vcloud:role:" + urllib.parse.quote(role)
    status, payload = post_form_json(cfg, f"{oauth_path(cfg)}/register", bearer, body)
    if status not in (200, 201) or "client_id" not in payload:
        fail("Create service account", status, payload)
    client_id = payload["client_id"]
    # Require Rotation is always turned off, so the refresh token stays valid. The register
    # body has no rotation field, so the new account is found by the software_id sent above.
    sa = find_service_account(cfg, bearer, software_id=body["software_id"])
    set_require_rotation(cfg, bearer, sa["id"], required=False)

    data = device_login({**cfg, "client_id": client_id}, bearer)
    print(f"Service account '{args.name}' created and granted.")
    print(f"Client ID:     {client_id}")
    print(f"Refresh token: {data['refresh_token']}")


def post_form_json(cfg: dict, path: str, bearer: str, body: dict) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    return http("POST", f"https://{cfg['host']}{path}", headers, json.dumps(body).encode())


def cmd_list(cfg: dict, _args: argparse.Namespace) -> None:
    accounts, total = fetch_service_accounts(cfg, admin_bearer(cfg))
    rows = [
        (str(sa.get("name", "")), str(sa.get("status", "")),
         "on" if sa.get("requireRotation") else "off",
         str((sa.get("org") or {}).get("name", "")), str(sa.get("id", "")))
        for sa in accounts
    ]
    headers = ("NAME", "STATUS", "ROTATION", "ORG", "ID")
    # Size each column to its longest value so long names don't push the others out of line.
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers).rstrip())
    for row in rows:
        print(fmt.format(*row).rstrip())
    print(f"\nShowing {len(accounts)} of {total} service accounts.")
    if total != len(accounts):
        print("The server reports more accounts than were returned. Check the token's org and rights.")


def fetch_service_accounts(cfg: dict, bearer: str) -> tuple[list[dict], int]:
    """Fetch every page of service accounts. Returns (accounts, resultTotal reported by the server)."""
    accounts: list[dict] = []
    page, total = 1, None
    while True:
        status, payload = api(cfg, "GET", f"/cloudapi/1.0.0/serviceAccounts?page={page}&pageSize=32", bearer)
        if status != 200:
            fail("List service accounts", status, payload)
        values = payload.get("values", []) if isinstance(payload, dict) else payload
        total = payload.get("resultTotal", len(values)) if isinstance(payload, dict) else len(values)
        accounts.extend(values)
        if not values or len(accounts) >= total:
            return accounts, total
        page += 1


def list_service_accounts(cfg: dict, bearer: str) -> list[dict]:
    return fetch_service_accounts(cfg, bearer)[0]


def find_service_account(cfg: dict, bearer: str, *, name: str | None = None, software_id: str | None = None) -> dict:
    matches = [
        sa for sa in list_service_accounts(cfg, bearer)
        if (name is None or sa.get("name") == name) and (software_id is None or sa.get("softwareId") == software_id)
    ]
    if len(matches) != 1:
        sys.exit(f"Expected one service account matching name={name!r} software_id={software_id!r}, found {len(matches)}.")
    return matches[0]


def set_require_rotation(cfg: dict, bearer: str, sa_id: str, required: bool) -> dict:
    """Turn refresh-token rotation on or off.

    Reads the full object and PUTs it back with requireRotation/tokenRotation changed,
    so fields the PUT does not mention are not dropped. Whether PUT is a partial update
    is not documented, so the read-modify-write is the safe option.
    """
    path = f"/cloudapi/1.0.0/serviceAccounts/{urllib.parse.quote(sa_id, safe=':')}"
    status, sa = api(cfg, "GET", path, bearer)
    if status != 200:
        fail("Get service account", status, sa)
    sa["requireRotation"] = required
    sa["tokenRotation"] = "ALWAYS" if required else "NEVER"
    status, updated = api(cfg, "PUT", path, bearer, sa)
    if status != 200:
        fail("Update service account", status, updated)
    return updated


def jwt_claims(token: str) -> dict:
    """Decode a JWT payload without verifying it. For troubleshooting only."""
    import base64
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def cmd_whoami(cfg: dict, _args: argparse.Namespace) -> None:
    """Show who the admin token belongs to, from the access token's claims.

    Prints claim names and values except the token itself. Use it to compare two tokens.
    """
    claims = jwt_claims(admin_bearer(cfg))
    for key in sorted(claims):
        value = claims[key]
        if isinstance(value, (list, dict)):
            value = json.dumps(value)
        print(f"{key:<24} {value}")


def cmd_delete(cfg: dict, args: argparse.Namespace) -> None:
    bearer = admin_bearer(cfg)
    sa = {"id": args.id} if args.id else find_service_account(cfg, bearer, name=args.name)
    label = args.name or sa["id"]
    if not args.yes:
        answer = input(f"Delete service account '{label}' ({sa['id']})? Type 'yes' to confirm: ")
        if answer.strip().lower() != "yes":
            sys.exit("Not deleted.")
    path = f"/cloudapi/1.0.0/serviceAccounts/{urllib.parse.quote(sa['id'], safe=':')}"
    status, payload = api(cfg, "DELETE", path, bearer)
    if status == 202:
        # Accepted but processed asynchronously; the account may still show for a moment.
        print(f"Delete accepted for service account '{label}' ({sa['id']}). The server is processing it; run list to confirm.")
        return
    if status not in (200, 204):
        fail("Delete service account", status, payload)
    print(f"Deleted service account '{label}' ({sa['id']}).")


def device_login(cfg: dict, bearer: str | None) -> dict:
    """Device flow: request a user code, approve it, poll for the refresh token.

    With an admin bearer, the request is approved through the API. Without one, the
    user code is printed for approval in the GUI. Returns the token data.
    """
    # 1. Ask for a device code and user code. The service account becomes "Requested".
    status, dev = post_form(oauth_url(cfg, "device_authorization"), {"client_id": cfg["client_id"]})
    if status != 200 or "device_code" not in dev:
        fail("device_authorization", status, dev)

    # 2. Approve the request. With admin credentials this is the API equivalent of
    #    Review Access Requests > Lookup > Grant. Without them, approve in the GUI.
    if bearer:
        verify_pending_request(cfg, bearer, dev["user_code"])
        status, payload = api(cfg, "POST", "/cloudapi/1.0.0/deviceLookup/grant",
                              bearer, {"userCode": dev["user_code"]})
        if status not in (200, 204):
            fail("Grant device authorization", status, payload)
        print(f"Granted access for user code {dev['user_code']}.")
    else:
        uri = dev.get("verification_uri_complete") or dev.get("verification_uri")
        print("No admin API token set. Approve this in the VCFA GUI:")
        print(f"  URL:       {uri}")
        print(f"  User code: {dev.get('user_code')}")

    # 3. Poll the token endpoint until the grant is in place.
    # Poll first and sleep only between retries. An approval that is already in place
    # (as with the API grant) is picked up immediately instead of after a full interval.
    interval = int(dev.get("interval", 5))
    deadline = time.time() + int(dev.get("expires_in", 3600))
    while time.time() < deadline:
        status, payload = post_form(oauth_url(cfg, "token"), {
            "grant_type": DEVICE_GRANT,
            "client_id": cfg["client_id"],
            "device_code": dev["device_code"],
        })
        if status == 200 and "access_token" in payload:
            return token_response(payload)
        error = payload.get("error")
        if error == "slow_down":
            interval += 5
        elif error != "authorization_pending":
            fail(f"Device login ({error or 'unknown error'})", status, payload)
        time.sleep(interval)
    sys.exit("Device code expired before approval. Run create again.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared by every command, so --org works after the command name:
    #   vcfa_sa.py create --org other-org --name my-svc
    org_opts = argparse.ArgumentParser(add_help=False)
    org_opts.add_argument("--org", help="tenant org to act in (default: the provider org)")
    org_opts.add_argument("--user", help="log in as this user (e.g. admin@System) instead of using a token; "
                                         "the password is taken from VCFA_PASSWORD or prompted for")
    org_opts.add_argument("--admin-token", help="admin API token (default: VCFA_ADMIN_REFRESH_TOKEN); "
                                                "prefer .env, as command-line args end up in shell history")
    tls = org_opts.add_argument_group("TLS")
    tls.add_argument("--ca-file", metavar="PATH", help="PEM CA certificate that signed the VCFA server (self-signed/private CA)")
    tls.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (last resort)")

    create = sub.add_parser("create", parents=[org_opts],
                            help="register, grant and print the refresh token of a new service account")
    create.add_argument("--name", required=True, help="client_name shown in the GUI")
    create.add_argument("--software-id", help="UUID; generated if omitted")
    create.add_argument("--software-version")
    create.add_argument("--client-uri")
    create.add_argument("--scope", metavar="ROLE", help="role name, e.g. 'Organization Administrator' "
                        "(default: System Administrator for provider, Organization Administrator for a tenant org)")

    sub.add_parser("list", parents=[org_opts], help="list service accounts")
    sub.add_parser("whoami", parents=[org_opts], help="show the user and roles behind the admin token")

    delete = sub.add_parser("delete", parents=[org_opts], help="delete a service account")
    dtarget = delete.add_mutually_exclusive_group(required=True)
    dtarget.add_argument("--name", help="service account name")
    dtarget.add_argument("--id", help="service account id URN")
    delete.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    return parser


COMMANDS = {
    "create": cmd_create,
    "list": cmd_list,
    "delete": cmd_delete,
    "whoami": cmd_whoami,
}


def main() -> None:
    global SSL_CONTEXT
    args = build_parser().parse_args()
    if args.ca_file and args.insecure:
        sys.exit("Use either --ca-file or --insecure, not both.")
    SSL_CONTEXT = make_ssl_context(args.ca_file, args.insecure)
    COMMANDS[args.command](config(args), args)


if __name__ == "__main__":
    main()
