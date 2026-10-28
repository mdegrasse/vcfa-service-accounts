#!/usr/bin/env python3
"""Create, approve and token-manage VCF Automation tenant service accounts.

Automates the flow that was previously done by hand in the GUI and Bruno:

  create    register, turn Require Rotation off, approve via API, print refresh token
  list      GET  /cloudapi/1.0.0/serviceAccounts         list service accounts
  rotation  set Require Rotation on or off for an account
  login     POST /oauth/tenant/{org}/device_authorization  request a device/user code
            POST /cloudapi/1.0.0/deviceLookup/grant        approve it (was "Review Access Requests")
            POST /oauth/tenant/{org}/token                 device-code grant -> refresh token
  refresh   POST /oauth/tenant/{org}/token                 refresh_token grant
  token     print a valid access token (refreshes if needed)
  status    show what is stored (no secrets)
  logout    delete the stored tokens

create, list and login's automatic approval need an admin credential:
VCFA_ADMIN_REFRESH_TOKEN, an API token from My Account > API Tokens of an org admin.
Without it, login falls back to printing the user code for manual approval in the GUI.

Configuration (environment variables, or a local .env file):
  VCFA_HOST                 e.g. automation.example.com (no scheme)
  VCFA_ORG                  tenant/org name
  VCFA_CLIENT_ID            client id of the service account (set after create)
  VCFA_ADMIN_REFRESH_TOKEN  optional, see above
"""

import argparse
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
TOKEN_DIR = PROJECT_DIR / "tokens"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_GRANT = "refresh_token"
REQUEST_TIMEOUT = 30
REFRESH_MARGIN_SECONDS = 60
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


def config(args: argparse.Namespace, need_client_id: bool = True) -> dict:
    """Build the run configuration. --org/--client-id override the .env defaults.

    VCFA_CLIENT_ID and VCFA_ADMIN_REFRESH_TOKEN belong to the default org (VCFA_ORG).
    They are only used when that org is targeted, so a token for one org is never
    sent to another. For any other org, use --client-id and VCFA_ADMIN_REFRESH_TOKEN_<ORG>.
    """
    load_dotenv(PROJECT_DIR / ".env")
    host = os.environ.get("VCFA_HOST", "").strip()
    default_org = os.environ.get("VCFA_ORG", "").strip()
    org = (args.org or default_org).strip()
    is_default_org = org == default_org

    # create and list do not take --client-id, so read it with a default.
    client_id = (getattr(args, "client_id", None) or (os.environ.get("VCFA_CLIENT_ID", "").strip() if is_default_org else "")).strip()

    admin_var = "VCFA_ADMIN_REFRESH_TOKEN_" + "".join(c if c.isalnum() else "_" for c in org.upper())
    admin_refresh = os.environ.get(admin_var, "").strip()
    if not admin_refresh and is_default_org:
        admin_refresh = os.environ.get("VCFA_ADMIN_REFRESH_TOKEN", "").strip()

    cfg = {"host": host, "org": org, "client_id": client_id, "admin_refresh": admin_refresh}
    required = {"VCFA_HOST": host, "org (--org or VCFA_ORG)": org}
    if need_client_id:
        required["client id (--client-id or VCFA_CLIENT_ID)"] = client_id
    missing = [name for name, value in required.items() if not value]
    if missing:
        sys.exit("Missing configuration: " + ", ".join(missing))
    if "://" in host:
        sys.exit("VCFA_HOST must be a bare host name, without https://")
    return cfg


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


def tenant_url(cfg: dict, endpoint: str) -> str:
    return f"https://{cfg['host']}/oauth/tenant/{cfg['org']}/{endpoint}"


def fail(what: str, status: int, payload: dict) -> None:
    detail = payload.get("error_description") or payload.get("message") or payload.get("error") or ""
    sys.exit(f"{what} failed ({status}): {detail}".rstrip(": ").rstrip())


# --- admin credential -------------------------------------------------------

def admin_bearer(cfg: dict) -> str:
    """Exchange the admin API token for a short-lived bearer token."""
    if not cfg["admin_refresh"]:
        sys.exit("This command needs VCFA_ADMIN_REFRESH_TOKEN (an org admin API token).")
    status, payload = post_form(tenant_url(cfg, "token"), {
        "grant_type": REFRESH_GRANT,
        "refresh_token": cfg["admin_refresh"],
    })
    if status != 200 or "access_token" not in payload:
        fail("Admin token exchange", status, payload)
    return payload["access_token"]


# --- token storage ----------------------------------------------------------

def token_file(cfg: dict) -> Path:
    # One file per org and client so several service accounts can coexist.
    return TOKEN_DIR / f"{cfg['org']}_{cfg['client_id']}.json"


def load_tokens(cfg: dict) -> dict | None:
    path = token_file(cfg)
    return json.loads(path.read_text()) if path.is_file() else None


def save_tokens(cfg: dict, data: dict) -> None:
    TOKEN_DIR.mkdir(mode=0o700, exist_ok=True)
    # Create with 0600 so the secret is never world-readable, even briefly.
    fd = os.open(token_file(cfg), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)


def store_token_response(cfg: dict, payload: dict, previous: dict | None = None) -> dict:
    """Persist a token response, keeping the old refresh token if none was returned."""
    refresh = payload.get("refresh_token") or (previous or {}).get("refresh_token")
    if not refresh:
        sys.exit("Token response contained no refresh_token; nothing stored.")
    data = {
        "access_token": payload.get("access_token"),
        "refresh_token": refresh,
        "expires_at": time.time() + int(payload.get("expires_in", 0)),
    }
    save_tokens(cfg, data)
    return data


def refresh_tokens(cfg: dict, stored: dict) -> dict:
    if not stored.get("refresh_token"):
        sys.exit("No stored refresh token. Run 'login' first.")
    status, payload = post_form(tenant_url(cfg, "token"), {
        "grant_type": REFRESH_GRANT,
        "client_id": cfg["client_id"],
        "refresh_token": stored["refresh_token"],
    })
    if status != 200 or "access_token" not in payload:
        fail("Refresh", status, payload)
    return store_token_response(cfg, payload, previous=stored)


# --- commands ---------------------------------------------------------------

def cmd_create(cfg: dict, args: argparse.Namespace) -> None:
    """Create a service account end to end and print its refresh token.

    Steps: register, turn Require Rotation off, device flow with API approval, store the
    refresh token. The register body follows the provider-side sample in the VCF Automation
    docs (software_id marks a service account). The tenant-side scope/role field is not
    documented, so it is passed through only if --scope is given. Verify on first use.
    """
    bearer = admin_bearer(cfg)
    body = {
        "client_name": args.name,
        "software_id": args.software_id or str(uuid.uuid4()),
        "software_version": args.software_version,
        "client_uri": args.client_uri,
    }
    if args.scope:
        body["scope"] = args.scope
    status, payload = post_form_json(cfg, f"/oauth/tenant/{cfg['org']}/register", bearer, body)
    if status not in (200, 201) or "client_id" not in payload:
        fail("Create service account", status, payload)
    client_id = payload["client_id"]
    if not args.keep_rotation:
        # The register body has no rotation field, so turn it off on the new account.
        # Looked up by the software_id we just sent, which is unique per account.
        sa = find_service_account(cfg, bearer, software_id=body["software_id"])
        set_require_rotation(cfg, bearer, sa["id"], required=False)

    login_cfg = {**cfg, "client_id": client_id}
    data = device_login(login_cfg, bearer)
    print(f"Service account '{args.name}' created and granted.")
    print(f"Client ID:     {client_id}")
    print(f"Refresh token: {data['refresh_token']}")
    print(f"Stored in:     {token_file(login_cfg)}")


def post_form_json(cfg: dict, path: str, bearer: str, body: dict) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    return http("POST", f"https://{cfg['host']}{path}", headers, json.dumps(body).encode())


def cmd_list(cfg: dict, _args: argparse.Namespace) -> None:
    status, payload = api(cfg, "GET", "/cloudapi/1.0.0/serviceAccounts", admin_bearer(cfg))
    if status != 200:
        fail("List service accounts", status, payload)
    print(json.dumps(payload, indent=2))


def list_service_accounts(cfg: dict, bearer: str) -> list[dict]:
    status, payload = api(cfg, "GET", "/cloudapi/1.0.0/serviceAccounts", bearer)
    if status != 200:
        fail("List service accounts", status, payload)
    # The collection may come wrapped in "values" (CloudAPI style) or as a bare list.
    return payload.get("values", []) if isinstance(payload, dict) else payload


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


def cmd_rotation(cfg: dict, args: argparse.Namespace) -> None:
    bearer = admin_bearer(cfg)
    if args.id:
        sa_id = args.id
    else:
        sa_id = find_service_account(cfg, bearer, name=args.name)["id"]
    updated = set_require_rotation(cfg, bearer, sa_id, required=args.on)
    print(f"Require Rotation is now {'ON' if updated.get('requireRotation') else 'OFF'} for {updated.get('name')} ({sa_id})")


def cmd_login(cfg: dict, _args: argparse.Namespace) -> None:
    bearer = admin_bearer(cfg) if cfg["admin_refresh"] else None
    device_login(cfg, bearer)
    print(f"Logged in. Tokens stored in {token_file(cfg)}")


def device_login(cfg: dict, bearer: str | None) -> dict:
    """Device flow: request a user code, approve it, poll for the refresh token, store it.

    With an admin bearer, the request is approved through the API. Without one, the
    user code is printed for approval in the GUI. Returns the stored token data.
    """
    # 1. Ask for a device code and user code. The service account becomes "Requested".
    status, dev = post_form(tenant_url(cfg, "device_authorization"), {"client_id": cfg["client_id"]})
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
        print("No VCFA_ADMIN_REFRESH_TOKEN set. Approve this in the VCFA GUI:")
        print(f"  URL:       {uri}")
        print(f"  User code: {dev.get('user_code')}")

    # 3. Poll the token endpoint until the grant is in place.
    # Poll first and sleep only between retries. An approval that is already in place
    # (as with the API grant) is picked up immediately instead of after a full interval.
    interval = int(dev.get("interval", 5))
    deadline = time.time() + int(dev.get("expires_in", 3600))
    while time.time() < deadline:
        status, payload = post_form(tenant_url(cfg, "token"), {
            "grant_type": DEVICE_GRANT,
            "client_id": cfg["client_id"],
            "device_code": dev["device_code"],
        })
        if status == 200 and "access_token" in payload:
            return store_token_response(cfg, payload)
        error = payload.get("error")
        if error == "slow_down":
            interval += 5
        elif error != "authorization_pending":
            fail(f"Device login ({error or 'unknown error'})", status, payload)
        time.sleep(interval)
    sys.exit("Device code expired before approval. Run login again.")


def cmd_refresh(cfg: dict, _args: argparse.Namespace) -> None:
    stored = load_tokens(cfg)
    if not stored:
        sys.exit("No stored tokens. Run 'login' first.")
    data = refresh_tokens(cfg, stored)
    print(f"Refreshed access token, valid until {time.ctime(data['expires_at'])}")


def cmd_token(cfg: dict, _args: argparse.Namespace) -> None:
    stored = load_tokens(cfg)
    if not stored:
        sys.exit("No stored tokens. Run 'login' first.")
    still_valid = stored.get("expires_at", 0) - REFRESH_MARGIN_SECONDS > time.time()
    if stored.get("access_token") and still_valid:
        print(stored["access_token"])
        return
    print(refresh_tokens(cfg, stored)["access_token"])


def cmd_status(cfg: dict, _args: argparse.Namespace) -> None:
    stored = load_tokens(cfg)
    if not stored:
        print(f"No tokens stored for org '{cfg['org']}' / client '{cfg['client_id']}'.")
        return
    remaining = int(stored.get("expires_at", 0) - time.time())
    print(f"Org:           {cfg['org']}")
    print(f"Client ID:     {cfg['client_id']}")
    print("Refresh token: present")
    print(f"Access token:  {'expired' if remaining <= 0 else f'expires in {remaining}s'}")


def cmd_logout(cfg: dict, _args: argparse.Namespace) -> None:
    path = token_file(cfg)
    if path.is_file():
        path.unlink()
        print(f"Deleted {path}")
    else:
        print("Nothing to delete.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared by every command, so --org works after the command name:
    #   vcfa_sa.py login --org other-org --client-id ...
    org_opts = argparse.ArgumentParser(add_help=False)
    org_opts.add_argument("--org", help="tenant org to act in (default: VCFA_ORG)")
    tls = org_opts.add_argument_group("TLS")
    tls.add_argument("--ca-file", metavar="PATH", help="PEM CA certificate that signed the VCFA server (self-signed/private CA)")
    tls.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (last resort)")
    client_opts = argparse.ArgumentParser(add_help=False, parents=[org_opts])
    client_opts.add_argument("--client-id", help="service account client id (default: VCFA_CLIENT_ID)")

    create = sub.add_parser("create", parents=[org_opts],
                            help="register, grant and print the refresh token of a new service account")
    create.add_argument("--name", required=True, help="client_name shown in the GUI")
    create.add_argument("--software-id", help="UUID; generated if omitted")
    create.add_argument("--software-version")
    create.add_argument("--client-uri")
    create.add_argument("--scope", help="role/scope to grant, if the tenant API accepts one")
    create.add_argument("--keep-rotation", action="store_true", help="leave Require Rotation on (default: turn it off)")

    sub.add_parser("list", parents=[org_opts], help="list service accounts")

    rotation = sub.add_parser("rotation", parents=[org_opts], help="turn Require Rotation on or off")
    target = rotation.add_mutually_exclusive_group(required=True)
    target.add_argument("--name", help="service account name")
    target.add_argument("--id", help="service account id URN")
    state = rotation.add_mutually_exclusive_group(required=True)
    state.add_argument("--on", action="store_true", help="require refresh token rotation")
    state.add_argument("--off", action="store_true", help="do not require rotation (refresh token stays valid)")
    for name, help_text in [
        ("login", "device flow: request, approve, store tokens"),
        ("refresh", "refresh the stored access token"),
        ("token", "print a valid access token"),
        ("status", "show stored token state"),
        ("logout", "delete stored tokens"),
    ]:
        sub.add_parser(name, parents=[client_opts], help=help_text)
    return parser


COMMANDS = {
    "create": cmd_create,
    "list": cmd_list,
    "rotation": cmd_rotation,
    "login": cmd_login,
    "refresh": cmd_refresh,
    "token": cmd_token,
    "status": cmd_status,
    "logout": cmd_logout,
}


def main() -> None:
    global SSL_CONTEXT
    args = build_parser().parse_args()
    if args.ca_file and args.insecure:
        sys.exit("Use either --ca-file or --insecure, not both.")
    SSL_CONTEXT = make_ssl_context(args.ca_file, args.insecure)
    # create and list only need the org and admin token, not a client id.
    cfg = config(args, need_client_id=args.command not in ("create", "list", "rotation"))
    COMMANDS[args.command](cfg, args)


if __name__ == "__main__":
    main()
