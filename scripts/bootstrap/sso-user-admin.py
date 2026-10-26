#!/usr/bin/env python3
"""Commission a private, least-privilege user service. Never create or reset a human user."""
import base64
import copy
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
VAULT = "https://cmpsso-contoso-kv.vault.azure.net/"
HOST = "cmpsso-xxxxxxxxxx.indonesiacentral.cloudapp.azure.com"
ORIGIN, ENDPOINT = "https://" + HOST, "https://" + HOST + ":8443"
LOOPBACK = "http://127.0.0.1:8080"
REALM = "/admin/realms/cmp-pdf"
SECRET = "cmp-user-admin-client-secret"
PENDING = "pending-sso-bootstrap"
MARKER = "cmp-user-admin-v1"
ROLES = ("query-users", "view-users", "manage-users")
EFFECTIVE_ROLES = (*ROLES, "query-groups")
GUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
SUBJECTS = ("44ee44ee-ff55-aa66-bb77-88cc88cc88cc", "55ff55ff-aa66-bb77-cc88-99dd99dd99dd")
ROOT = Path("/var/lib/cmp-sso")
JOURNAL = ROOT / "user-admin-state.json"
CADDY = Path("/etc/caddy/Caddyfile")
IMDS = ("http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net")


class SafeError(RuntimeError):
    def __init__(self, stage, code=0):
        self.stage, self.code = stage, code
        super().__init__("User administration commissioning failed: " + stage)


def require(condition, stage):
    if not condition:
        raise SafeError(stage)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_payload(payload):
    require(isinstance(payload, dict) and set(payload) == {"operation", "ownershipId", "operationId", "baseAdminOwner",
            "foundationHash", "bootstrapHash", "tenantId", "vaultUri", "privateEndpoint", "allowCaddyRestart"},
            "payload-fields")
    require(payload["operation"] in ("preflight", "apply", "verify") and payload["tenantId"] == TENANT and
            payload["vaultUri"] == VAULT and payload["privateEndpoint"] == ENDPOINT and
            type(payload["allowCaddyRestart"]) is bool, "payload-scope")
    require(all(matches(GUID, payload[key]) and payload[key] != "00000000-0000-0000-0000-000000000000"
                for key in ("ownershipId", "operationId", "baseAdminOwner")) and
            all(matches(r"[a-f0-9]{64}", payload[key]) for key in ("foundationHash", "bootstrapHash")), "payload-ownership")


def allowed_private_request(method, path):
    if path == "/realms/cmp-pdf/protocol/openid-connect/token":
        return method == "POST"
    if path == REALM + "/users":
        return method in ("GET", "POST")
    if path == REALM + "/users/profile":
        return method == "GET"
    match = re.fullmatch(REALM + "/users/(" + GUID + r")(?:/(reset-password|logout|credentials|execute-actions-email))?", path)
    if not match:
        return False
    return method in {None: ("GET", "PUT"), "reset-password": ("PUT",), "logout": ("POST",),
                      "credentials": ("GET",), "execute-actions-email": ("PUT",)}[match[2]]


def expected_public_caddy():
    return f"""{{
    admin off
}}
http://{HOST} {{
    redir https://{HOST}{{uri}} permanent
}}
{HOST} {{
    @public path /realms/cmp-pdf /realms/cmp-pdf/* /resources/*
    handle @public {{
        reverse_proxy 127.0.0.1:8080
    }}
    handle {{
        respond 404
    }}
    header Strict-Transport-Security "max-age=31536000"
}}
"""


def private_caddy():
    # Each matcher combines exact method and bounded path. No general /admin prefix proxy.
    patterns = [
        ("token", "POST", "path /realms/cmp-pdf/protocol/openid-connect/token"),
        ("users", "GET POST", "path /admin/realms/cmp-pdf/users"),
        ("profile", "GET", "path /admin/realms/cmp-pdf/users/profile"),
        ("user", "GET PUT", "path_regexp user ^/admin/realms/cmp-pdf/users/" + GUID + "$"),
        ("password", "PUT", "path_regexp password ^/admin/realms/cmp-pdf/users/" + GUID + "/reset-password$"),
        ("logout", "POST", "path_regexp logout ^/admin/realms/cmp-pdf/users/" + GUID + "/logout$"),
        ("credentials", "GET", "path_regexp credentials ^/admin/realms/cmp-pdf/users/" + GUID + "/credentials$"),
        ("actions", "PUT", "path_regexp actions ^/admin/realms/cmp-pdf/users/" + GUID + "/execute-actions-email$"),
    ]
    lines = [f"\nhttps://{HOST}:8443 {{", "    bind 10.42.4.4"]
    for name, methods, path in patterns:
        lines += ["    @" + name + " {", "        method " + methods, "        " + path, "    }",
                  "    handle @" + name + " {", "        reverse_proxy 127.0.0.1:8080", "    }"]
    lines += ["    handle {", "        respond 404", "    }",
              '    header Strict-Transport-Security "max-age=31536000"', "}", ""]
    return "\n".join(lines)


def combined_caddy(current):
    original = expected_public_caddy()
    desired = original + private_caddy()
    require(current in (original, desired), "unknown-caddy-config-no-adoption")
    return desired


def reload_method(version, allow_restart):
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)(?:\s|$)", version)
    require(match is not None, "caddy-version-unverified")
    if tuple(map(int, match.groups())) >= (2, 11, 0):
        return "signal"
    require(allow_restart, "old-caddy-admin-off-requires-explicit-caddy-only-restart-approval")
    return "caddy-only-restart"


def checked_addresses(host, network):
    try:
        values = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        require(0 < len(values) <= 16 and all(ipaddress.ip_address(item) in ipaddress.ip_network(network) for item in values),
                "private-dns")
        return values
    except SafeError:
        raise
    except Exception:
        raise SafeError("private-dns") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except Exception:
            self.sock.close()
            raise


class PinnedHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, address):
        super().__init__(context=ssl.create_default_context())
        self.address = address

    def https_open(self, req):
        return self.do_open(lambda host, **kw: PinnedConnection(host, self.address, **kw), req, context=self._context)


def loopback_allowed(path, method):
    if path == "/realms/master/protocol/openid-connect/token":
        return method == "POST"
    if path == REALM:
        return method == "GET"
    if not path.startswith(REALM + "/"):
        return False
    part = path[len(REALM):]
    if part == "/clients":
        return method in ("GET", "POST")
    if part == "/users/profile":
        return method in ("GET", "PUT")
    if matches(r"/clients/" + GUID + r"(?:/(?:service-account-user|client-secret|roles/(?:query-users|view-users|manage-users|query-groups)(?:/composites)?))?", part):
        return method == "GET"
    if matches(r"/(?:users/" + GUID + r"/role-mappings|clients/" + GUID + r"/scope-mappings)/clients/" + GUID + r"(?:/composite)?", part):
        return method in ("GET", "POST") and (method != "POST" or not part.endswith("/composite"))
    return matches(r"/users/(?:" + "|".join(SUBJECTS) + r")(?:/(?:credentials|federated-identity))?", part) and method == "GET"


def request(url, method="GET", body=None, headers=None, form=False):
    parsed = urllib.parse.urlsplit(url)
    require(not parsed.username and not parsed.password and not parsed.fragment, "transport-target")
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    vault = parsed.scheme == "https" and parsed.netloc == urllib.parse.urlsplit(VAULT).netloc
    private = parsed.scheme == "https" and parsed.netloc == HOST + ":8443"
    loopback = parsed.scheme == "http" and parsed.netloc == "127.0.0.1:8080" and loopback_allowed(parsed.path, method)
    imds = url == IMDS and method == "GET" and body is None and headers == {"Metadata": "true"}
    if vault:
        require(parsed.query == "api-version=7.4" and parsed.path in ("/secrets/" + SECRET, "/secrets/keycloak-admin-password") and
                (method == "GET" or method == "PUT" and parsed.path == "/secrets/" + SECRET), "vault-target")
        addresses = checked_addresses(parsed.hostname, "10.42.3.0/24")
        handlers.append(PinnedHTTPS(addresses[0]))
    elif private:
        require(allowed_private_request(method, parsed.path), "private-api-path")
        handlers.append(PinnedHTTPS("10.42.4.4"))
    else:
        require(loopback or imds, "transport-target")
    data = None
    headers = dict(headers or {})
    if body is not None:
        data = (urllib.parse.urlencode(body) if form else json.dumps(body, separators=(",", ":"))).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    for attempt in range(18 if vault and method == "GET" else 3):
        try:
            with urllib.request.build_opener(*handlers).open(
                    urllib.request.Request(url, method=method, data=data, headers=headers), timeout=20) as response:
                raw = response.read(1048577)
                require(len(raw) <= 1048576, "response-size")
                return json.loads(raw, object_pairs_hook=unique) if raw else None
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            if method == "GET" and code in (403, 429, 500, 502, 503, 504) and attempt < (17 if vault else 2):
                time.sleep(min(2 ** attempt, 8))
                continue
            raise SafeError("http", code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise SafeError("transport") from None


def token():
    checked_addresses(urllib.parse.urlsplit(VAULT).hostname, "10.42.3.0/24")
    result = request(IMDS, headers={"Metadata": "true"})
    require(isinstance(result, dict) and isinstance(result.get("access_token"), str), "managed-identity")
    return result["access_token"]


class Vault:
    def __init__(self):
        self.headers = {"Authorization": "Bearer " + token()}

    def get(self):
        return request(VAULT + "secrets/" + SECRET + "?api-version=7.4", headers=self.headers)

    def put(self, value):
        return request(VAULT + "secrets/" + SECRET + "?api-version=7.4", "PUT",
                       {"value": value, "attributes": {"enabled": True}, "tags": {"costcontrol": "ignore"}}, self.headers)


class Keycloak:
    def __init__(self):
        admin = request(VAULT + "secrets/keycloak-admin-password?api-version=7.4",
                        headers={"Authorization": "Bearer " + token()})
        require(isinstance(admin, dict) and isinstance(admin.get("value"), str) and
                16 <= len(admin["value"]) <= 512 and admin["value"] != PENDING, "bootstrap-admin")
        auth = request(LOOPBACK + "/realms/master/protocol/openid-connect/token", "POST",
                       {"client_id": "admin-cli", "grant_type": "password", "username": "cmpbootstrap",
                        "password": admin.pop("value")}, form=True)
        require(isinstance(auth, dict) and isinstance(auth.get("access_token"), str), "bootstrap-auth")
        self.headers = {"Authorization": "Bearer " + auth["access_token"]}

    def __call__(self, path, method="GET", body=None):
        require(isinstance(path, str) and ".." not in path and "#" not in path and "://" not in path, "loopback-path")
        return request(LOOPBACK + REALM + path, method, body, self.headers)


class Journal:
    def __init__(self):
        require(os.geteuid() == 0, "root-required")
        for parent in reversed(ROOT.parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "journal-parent")
        ROOT.mkdir(mode=0o700, exist_ok=True)
        info = ROOT.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "journal-directory")

    def load(self):
        pending = JOURNAL.with_suffix(".pending")
        require(not pending.exists() and not pending.is_symlink(), "journal-checkpoint-uncertain")
        if not JOURNAL.exists() and not JOURNAL.is_symlink():
            return None
        info = JOURNAL.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077 and info.st_size <= 16384,
                "journal-permissions")
        with os.fdopen(os.open(JOURNAL, os.O_RDONLY | os.O_NOFOLLOW), "r") as stream:
            return json.loads(stream.read(16385), object_pairs_hook=unique)

    def save(self, value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        require(len(raw) <= 16384, "journal-size")
        atomic_file(JOURNAL, raw, 0o600, 0)


def atomic_file(path, data, mode, group):
    pending = path.with_suffix(".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def client_representation(payload):
    return {"clientId": "cmp-user-admin", "name": "CMP user administration (private)", "protocol": "openid-connect",
            "enabled": True, "publicClient": False, "bearerOnly": False, "clientAuthenticatorType": "client-secret",
            "standardFlowEnabled": False, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True, "fullScopeAllowed": False, "authorizationServicesEnabled": False,
            "redirectUris": [], "webOrigins": [], "defaultClientScopes": ["roles", "service_account"], "optionalClientScopes": [],
            "attributes": {"cmpUserAdminManaged": MARKER, "cmpUserAdminOwner": payload["ownershipId"],
                           "cmpUserAdminOperationId": payload["operationId"],
                           "oauth2.device.authorization.grant.enabled": "false", "oidc.ciba.grant.enabled": "false"}}


def profile_representation(profile):
    require(isinstance(profile, dict) and isinstance(profile.get("attributes"), list) and
            len(profile["attributes"]) <= 100, "profile-shape")
    result = copy.deepcopy(profile)
    for name in ("cmpUserManaged", "cmpUserOperationId"):
        desired = {"name": name, "displayName": name, "multivalued": False,
                   "permissions": {"view": ["admin"], "edit": ["admin"]}}
        found = [item for item in result["attributes"] if item.get("name") == name]
        require(not found or found == [desired], "profile-owned-attribute-conflict")
        if not found:
            result["attributes"].append(desired)
    return result


def subjects_snapshot(kc):
    return {subject: {"user": kc("/users/" + subject), "credentials": kc("/users/" + subject + "/credentials"),
                      "links": kc("/users/" + subject + "/federated-identity")} for subject in SUBJECTS}


def record_secret(record):
    require(isinstance(record, dict) and isinstance(record.get("value"), str) and
            record.get("attributes", {}).get("enabled") is True and
            matches(re.escape(VAULT + "secrets/" + SECRET + "/") + r"[a-f0-9]{32}", record.get("id")), "vault-record")
    return record


def role_keys(values):
    require(isinstance(values, list) and len(values) <= 4 and all(isinstance(item, dict) and
            matches(GUID, item.get("id")) and isinstance(item.get("name"), str) for item in values), "role-list-shape")
    result = {(item["id"], item["name"]) for item in values}
    require(len(result) == len(values), "duplicate-role")
    return result


def commission(kc, vault, journal, payload):
    validate_payload(payload)
    verifying = payload["operation"] == "verify"
    desired = {"schemaVersion": MARKER, "ownershipId": payload["ownershipId"], "operationId": payload["operationId"],
               "baseAdminOwner": payload["baseAdminOwner"], "foundationHash": payload["foundationHash"],
               "bootstrapHash": payload["bootstrapHash"], "clientStage": "new", "clientUuid": "",
               "rolesStage": "new", "profileStage": "new", "secretStage": "new", "secretFingerprint": "",
               "secretVersion": "", "caddyStage": "new", "caddyHash": ""}
    state = journal.load()
    exists = state is not None
    if not exists:
        require(not verifying, "missing-private-journal")
        state = desired
    require(isinstance(state, dict) and set(state) == set(desired) and all(state[key] == desired[key]
            for key in ("schemaVersion", "ownershipId", "operationId", "baseAdminOwner", "foundationHash", "bootstrapHash")),
            "private-journal-ownership")
    for key in ("clientStage", "rolesStage", "profileStage", "secretStage", "caddyStage"):
        require(state[key] in ("new", "complete"), "uncertain-write-explicit-recovery-required")
    realm = kc("")
    require(isinstance(realm, dict) and realm.get("realm") == "cmp-pdf" and realm.get("enabled") is True and
            realm.get("verifyEmail") is True, "realm-security-contract")
    subjects = subjects_snapshot(kc)
    profile = kc("/users/profile")
    desired_profile = profile_representation(profile)
    clients = kc("/clients?clientId=cmp-user-admin&max=2")
    require(isinstance(clients, list) and len(clients) <= 1, "ambiguous-client")
    stored = record_secret(vault.get())
    if state["clientStage"] == "new":
        require(not verifying and not clients and stored["value"] == PENDING, "unknown-existing-client-or-secret")
        journal.save(state)
        state["clientStage"] = "intent"
        journal.save(state)
        kc("/clients", "POST", client_representation(payload))
        clients = kc("/clients?clientId=cmp-user-admin&max=2")
        require(isinstance(clients, list) and len(clients) == 1 and matches(GUID, clients[0].get("id")), "client-create-unproven")
        state["clientUuid"], state["clientStage"] = clients[0]["id"], "complete"
        journal.save(state)
    require(len(clients) == 1 and clients[0].get("id") == state["clientUuid"] and matches(GUID, state["clientUuid"]),
            "owned-client-missing")
    client = kc("/clients/" + state["clientUuid"])
    representation = client_representation(payload)
    # Keycloak omits disabled authorization services and adds its service_account scope.
    require(isinstance(client, dict) and all(client.get(key) == value for key, value in representation.items()
            if key not in ("name", "attributes", "authorizationServicesEnabled", "defaultClientScopes")) and
            client.get("authorizationServicesEnabled", False) is False and
            isinstance(client.get("defaultClientScopes"), list) and
            len(client["defaultClientScopes"]) == 2 and set(client["defaultClientScopes"]) == {"roles", "service_account"} and
            all(client.get("attributes", {}).get(key) == value for key, value in representation["attributes"].items()),
            "owned-client-configuration")
    service = kc("/clients/" + state["clientUuid"] + "/service-account-user")
    require(isinstance(service, dict) and matches(GUID, service.get("id")) and service["id"] not in SUBJECTS and
            service.get("username") == "service-account-cmp-user-admin" and
            service.get("serviceAccountClientId", "cmp-user-admin") == "cmp-user-admin", "owned-service-account")
    management = kc("/clients?clientId=realm-management&max=2")
    require(isinstance(management, list) and len(management) == 1 and matches(GUID, management[0].get("id")), "realm-management-client")
    management_id = management[0]["id"]
    builtin = [kc("/clients/" + management_id + "/roles/" + name) for name in EFFECTIVE_ROLES]
    for name, role in zip(EFFECTIVE_ROLES, builtin):
        require(isinstance(role, dict) and role.get("name") == name and matches(GUID, role.get("id")) and
                role.get("clientRole") is True and role.get("containerId") == management_id and
                role.get("composite") is (name == "view-users"), "bounded-realm-management-role")
    roles = builtin[:3]
    # Keycloak's unmodified view-users composite includes query-groups (and query-users).
    inherited = role_keys(kc("/clients/" + management_id + "/roles/view-users/composites"))
    require(inherited == role_keys([builtin[0], builtin[3]]), "unexpected-builtin-view-users-composite")
    role_path = "/users/" + service["id"] + "/role-mappings/clients/" + management_id
    scope_path = "/clients/" + state["clientUuid"] + "/scope-mappings/clients/" + management_id
    mapped, scoped = kc(role_path), kc(scope_path)
    expected_roles = role_keys(roles)
    for value in (mapped, scoped):
        require(role_keys(value) <= expected_roles, "unexpected-service-privilege")
    effective_roles = role_keys(builtin)
    require(role_keys(kc(role_path + "/composite")) <= effective_roles, "unexpected-service-privilege")
    if state["rolesStage"] == "new":
        require(not verifying, "roles-not-commissioned")
        state["rolesStage"] = "intent"
        journal.save(state)
        for path, existing in ((role_path, mapped), (scope_path, scoped)):
            missing = [role for role in roles if (role["id"], role["name"]) not in role_keys(existing)]
            if missing:
                kc(path, "POST", missing)
    for path in (role_path, scope_path):
        actual = kc(path)
        require(len(actual) == 3 and role_keys(actual) == expected_roles, "role-scope-incomplete")
    require(role_keys(kc(role_path + "/composite")) == effective_roles, "effective-role-scope-incomplete")
    if state["rolesStage"] == "intent":
        state["rolesStage"] = "complete"
        journal.save(state)
    if state["profileStage"] == "new":
        require(not verifying, "profile-not-commissioned")
        state["profileStage"] = "intent"
        journal.save(state)
        require(kc("/users/profile") == profile, "profile-concurrent-change")
        if profile != desired_profile:
            kc("/users/profile", "PUT", desired_profile)
        require(kc("/users/profile") == desired_profile, "profile-write-unproven")
        state["profileStage"] = "complete"
        journal.save(state)
    require(kc("/users/profile") == desired_profile, "profile-drift")
    secret = kc("/clients/" + state["clientUuid"] + "/client-secret")
    require(isinstance(secret, dict) and isinstance(secret.get("value"), str) and 24 <= len(secret["value"]) <= 512,
            "client-secret")
    value = secret.pop("value")
    if state["secretStage"] == "new":
        require(not verifying and record_secret(vault.get())["value"] == PENDING, "unknown-existing-vault-secret")
        state["secretStage"], state["secretFingerprint"] = "intent", fingerprint(value)
        journal.save(state)
        result = record_secret(vault.put(value))
        confirmed = record_secret(vault.get())
        require(result["id"] == confirmed["id"] and confirmed["value"] == value, "vault-write-unproven")
        state["secretVersion"], state["secretStage"] = confirmed["id"], "complete"
        journal.save(state)
    stored = record_secret(vault.get())
    require(state["secretFingerprint"] == fingerprint(value) and stored["value"] == value and
            stored["id"] == state["secretVersion"], "client-secret-or-version-changed")
    require(subjects_snapshot(kc) == subjects, "unrelated-subjects-changed")
    return {"status": "ready", "operation": payload["operation"], "clientUuid": state["clientUuid"],
            "secretVersion": state["secretVersion"], "smtpConfigured": bool(realm.get("smtpServer", {}).get("host") and
            realm.get("smtpServer", {}).get("from")), "issuer": ORIGIN + "/realms/cmp-pdf", "loginVerified": False}


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=60)
    require(result.returncode == 0, "guest-command")
    return result.stdout.strip()


def caddy_preflight(payload):
    source = Path("/opt/cmp/sso-keycloak.py")
    info = source.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and
            fingerprint(source.read_text()) == payload["bootstrapHash"], "frozen-bootstrap-fingerprint")
    spec = importlib.util.spec_from_file_location("cmp_frozen_keycloak", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.caddy_config(ORIGIN) == expected_public_caddy(), "frozen-caddy-canonical")
    info = CADDY.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_size <= 32768,
            "caddyfile-permissions")
    require(CADDY.parent.lstat().st_uid == 0 and not CADDY.parent.lstat().st_mode & 0o022, "caddy-directory")
    current = CADDY.read_text()
    desired = combined_caddy(current)
    require(run("systemctl", "is-active", "caddy") == "active" and
            run("systemctl", "is-active", "cmp-sso-keycloak") == "active", "healthy-services-required")
    require(tls_status(443, "/realms/cmp-pdf/.well-known/openid-configuration") == 200 and
            tls_status(443, "/admin") == 404, "healthy-public-oidc-required")
    method = "not-needed" if current == desired else reload_method(run("caddy", "version"), payload["allowCaddyRestart"])
    if method != "not-needed":
        pid = run("systemctl", "show", "-p", "MainPID", "--value", "caddy")
        require(pid.isdigit() and int(pid) > 1, "caddy-pid")
        arguments = Path("/proc/" + pid + "/cmdline").read_bytes().split(b"\0")
        require(b"run" in arguments and b"--resume" not in arguments and
                b"/etc/caddy/Caddyfile" in arguments, "caddy-config-load-precondition")
    return method


def tls_status(port, path):
    connection = PinnedConnection(HOST, "10.42.4.4", port=port, timeout=10, context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers={"Host": HOST})
        response = connection.getresponse()
        response.read(1048576)
        return response.status
    finally:
        connection.close()


def verify_private(secret):
    auth = request(ENDPOINT + "/realms/cmp-pdf/protocol/openid-connect/token", "POST",
                   {"client_id": "cmp-user-admin", "client_secret": secret, "grant_type": "client_credentials"}, form=True)
    require(isinstance(auth, dict) and isinstance(auth.get("access_token"), str), "private-service-auth")
    try:
        part = auth["access_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)), object_pairs_hook=unique)
        require(claims.get("iss") == ORIGIN + "/realms/cmp-pdf" and claims.get("azp") == "cmp-user-admin" and
                set(claims.get("resource_access", {})) == {"realm-management"} and
                set(claims.get("resource_access", {}).get("realm-management", {}).get("roles", [])) == set(EFFECTIVE_ROLES),
                "private-service-token-scope")
    except (ValueError, IndexError):
        raise SafeError("private-token-shape") from None
    users = request(ENDPOINT + REALM + "/users?max=1", headers={"Authorization": "Bearer " + auth["access_token"]})
    require(isinstance(users, list) and len(users) <= 1, "private-service-query")
    require(tls_status(443, "/realms/cmp-pdf/.well-known/openid-configuration") == 200, "public-oidc-preserved")
    for port, path in ((443, "/admin"), (8443, REALM + "/clients"), (8443, REALM + "/roles"), (8443, REALM + "/groups"),
                       (8443, "/realms/master"), (8443, "/realms/cmp-pdf/protocol/openid-connect/token")):
        require(tls_status(port, path) == 404, "private-or-public-management-deny")


def load_caddy(method):
    if method == "signal":
        pid = int(run("systemctl", "show", "-p", "MainPID", "--value", "caddy"))
        require(pid > 1, "caddy-pid")
        os.kill(pid, signal.SIGUSR1)
    else:
        require(method == "caddy-only-restart", "caddy-load-method")
        run("systemctl", "restart", "caddy")


def configure_caddy(payload, journal, secret):
    import grp
    method = caddy_preflight(payload)
    state = journal.load()
    require(state is not None and state["caddyStage"] in ("new", "complete"), "caddy-journal-uncertain")
    desired = combined_caddy(CADDY.read_text())
    desired_hash = fingerprint(desired)
    if state["caddyStage"] == "complete":
        require(state["caddyHash"] == desired_hash and CADDY.read_text() == desired, "caddy-completed-config-changed")
        verify_private(secret)
        return desired_hash
    require(payload["operation"] == "apply", "caddy-not-commissioned")
    require(method in ("signal", "caddy-only-restart") and
            (method != "caddy-only-restart" or payload["allowCaddyRestart"]) and
            CADDY.read_text() == expected_public_caddy(), "caddy-new-operation-precondition")
    state["caddyStage"] = "intent"
    journal.save(state)
    before_pid = run("systemctl", "show", "-p", "MainPID", "--value", "cmp-sso-keycloak")
    backup = ROOT / "user-admin-Caddyfile.backup"
    require(not backup.exists() and not backup.is_symlink(), "unknown-caddy-backup")
    atomic_file(backup, CADDY.read_bytes(), 0o600, 0)
    require(backup.read_text() == expected_public_caddy(), "caddy-backup-fingerprint")
    run("caddy", "validate", "--config", str(backup), "--adapter", "caddyfile")
    gid = grp.getgrnam("caddy").gr_gid
    candidate = CADDY.with_name("Caddyfile.user-admin-candidate")
    require(not candidate.exists() and not candidate.is_symlink(), "unknown-caddy-candidate")
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), 0o640)
        stream.write(desired.encode())
        stream.flush()
        os.fsync(stream.fileno())
    run("caddy", "validate", "--config", str(candidate), "--adapter", "caddyfile")
    try:
        os.replace(candidate, CADDY)
        sync_directory(CADDY.parent)
        load_caddy(method)
        for attempt in range(30):
            try:
                if tls_status(8443, REALM + "/clients") == 404:
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            raise SafeError("private-caddy-readiness-unproven")
        verify_private(secret)
        require(run("systemctl", "is-active", "cmp-sso-keycloak") == "active" and
                run("systemctl", "show", "-p", "MainPID", "--value", "cmp-sso-keycloak") == before_pid,
                "healthy-keycloak-must-not-restart")
    except Exception:
        # Keep the intent journal and backup: an operator must reconcile any failed commissioning.
        try:
            require(backup.read_text() == expected_public_caddy(), "caddy-rollback-backup-changed")
            run("caddy", "validate", "--config", str(backup), "--adapter", "caddyfile")
            atomic_file(CADDY, backup.read_bytes(), 0o640, gid)
            load_caddy(method)
            require(run("systemctl", "is-active", "caddy") == "active" and tls_status(443, "/admin") == 404 and
                    tls_status(443, "/realms/cmp-pdf/.well-known/openid-configuration") == 200 and
                    run("systemctl", "show", "-p", "MainPID", "--value", "cmp-sso-keycloak") == before_pid,
                    "caddy-rollback-health")
        except Exception:
            raise SafeError("caddy-rollback-uncertain-explicit-recovery-required") from None
        raise SafeError("caddy-rolled-back-explicit-recovery-required") from None
    state["caddyStage"], state["caddyHash"] = "complete", desired_hash
    journal.save(state)
    return desired_hash


def main():
    stage = "protected-payload"
    try:
        require(os.geteuid() == 0, "root-required")
        raw = os.environ.pop("CMP_USER_ADMIN_PAYLOAD", None)
        require(isinstance(raw, str) and 0 < len(raw.encode()) <= 4096, stage)
        payload = json.loads(raw, object_pairs_hook=unique)
        raw = None
        validate_payload(payload)
        config = Path("/etc/cmp-sso-keycloak.json")
        info = config.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "guest-config-permissions")
        value = json.loads(config.read_text(), object_pairs_hook=unique)
        require(value.get("origin") == ORIGIN and value.get("tenant_id") == TENANT and
                value.get("vault_uri") == VAULT and value.get("host") == "postgres.cmpsso.internal", "guest-config-scope")
        stage = "caddy-preflight"
        caddy_preflight(payload)
        if payload["operation"] == "preflight":
            require(CADDY.read_text() == expected_public_caddy() and not JOURNAL.exists() and
                    not JOURNAL.is_symlink() and not JOURNAL.with_suffix(".pending").exists(),
                    "preflight-unknown-existing-user-admin-artifact")
            proof = {"status": "ready", "operation": "preflight", "issuer": ORIGIN + "/realms/cmp-pdf",
                     "privateEndpoint": ENDPOINT, "loginVerified": False}
        else:
            stage = "owned-private-commissioning"
            journal = Journal()
            import fcntl
            fd = os.open(str(JOURNAL) + ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "journal-lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                vault = Vault()
                proof = commission(Keycloak(), vault, journal, payload)
                proof["caddyHash"] = configure_caddy(payload, journal, record_secret(vault.get())["value"])
                proof["privateEndpoint"] = ENDPOINT
                proof["queryVerified"] = True
            finally:
                os.close(fd)
        output = json.dumps(proof, separators=(",", ":"))
        require(len(output.encode()) <= 4096, "public-proof-size")
        print(output)
        return 0
    except Exception as error:
        safe = error if isinstance(error, SafeError) else SafeError(stage)
        print(json.dumps({"status": "failed", "stage": safe.stage, "httpCode": safe.code}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
