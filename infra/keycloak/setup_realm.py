#!/usr/bin/env python3
"""
Bootstrap script for Keycloak tfm realm.
Run after: docker compose up -d postgres keycloak
Usage: python3 infra/keycloak/setup_realm.py

KC 26.2 notes:
- token-exchange:v1 (legacy) is enabled via KC_FEATURES=token-exchange in docker-compose.
- admin-fine-grained-authz is NOT used; instead, Audience protocol mappers are added to
  each client so that KC V1 can verify the requesting client is in the subject_token aud.
"""

import sys
import time
import requests

KEYCLOAK_URL = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
REALM = "tfm"

CUSTOM_SCOPES = [
    ("read:accounts",     "Allows calling read_account_balance"),
    ("read:transactions", "Allows reading transaction history"),
    ("write:transfers",   "Allows initiate_transfer (requires step-up)"),
    ("read:documents",    "Allows read_internal_doc"),
]

MCP_RESOURCE_URI = "http://localhost:8001"


def get_admin_token() -> str:
    resp = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def wait_for_keycloak(retries: int = 30, delay: int = 3) -> None:
    print("Waiting for Keycloak to be ready...")
    for i in range(retries):
        try:
            r = requests.get(f"{KEYCLOAK_URL}/realms/master", timeout=5)
            if r.status_code == 200:
                print("Keycloak is ready.")
                return
        except requests.exceptions.ConnectionError:
            pass
        print(f"  attempt {i+1}/{retries}...")
        time.sleep(delay)
    sys.exit("Keycloak did not become ready in time.")


def h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_realm(token: str) -> None:
    r = requests.post(f"{KEYCLOAK_URL}/admin/realms", headers=h(token), timeout=10, json={
        "realm": REALM, "enabled": True, "displayName": "TFM PoC",
        "accessTokenLifespan": 300,
    })
    if r.status_code == 409:
        print(f"  realm '{REALM}' already exists.")
    else:
        r.raise_for_status()
        print(f"  realm '{REALM}' created.")


def get_scope_map(token: str) -> dict:
    scopes = requests.get(f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes",
                          headers=h(token), timeout=10).json()
    return {s["name"]: s["id"] for s in scopes}


def create_client_scope(token: str, name: str, description: str) -> None:
    r = requests.post(f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes", headers=h(token),
                      timeout=10, json={
        "name": name, "description": description, "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true"},
    })
    if r.status_code == 409:
        print(f"  scope '{name}' already exists.")
    else:
        r.raise_for_status()
        print(f"  scope '{name}' created.")


def assign_optional_scopes(token: str, client_uuid: str, client_id: str,
                           scope_map: dict, scope_names: list) -> None:
    for name in scope_names:
        sid = scope_map.get(name)
        if not sid:
            continue
        r = requests.put(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/optional-client-scopes/{sid}",
            headers=h(token), timeout=10,
        )
        if r.status_code not in (200, 204):
            print(f"    WARN: assign scope '{name}' to '{client_id}': {r.status_code}")


def add_audience_mapper(token: str, client_uuid: str, name: str,
                        audience: str, is_client: bool = True) -> None:
    config = {"id.token.claim": "false", "access.token.claim": "true"}
    if is_client:
        config["included.client.audience"] = audience
    else:
        config["included.custom.audience"] = audience

    existing = requests.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
        headers=h(token), timeout=10,
    ).json()
    if any(m.get("name") == name for m in existing):
        print(f"    mapper '{name}' already exists.")
        return

    r = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
        headers=h(token), timeout=10, json={
            "name": name, "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False, "config": config,
        },
    )
    if r.status_code in (200, 201, 204):
        print(f"    mapper '{name}' added.")
    else:
        print(f"    WARN mapper '{name}': {r.status_code} {r.text[:80]}")


def create_client(token: str, payload: dict) -> str:
    client_id = payload["clientId"]
    r = requests.post(f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
                      json=payload, headers=h(token), timeout=10)
    if r.status_code == 409:
        print(f"  client '{client_id}' already exists.")
    else:
        r.raise_for_status()
        print(f"  client '{client_id}' created.")
    return requests.get(f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
                        headers=h(token), params={"clientId": client_id},
                        timeout=10).json()[0]["id"]


def get_client_secret(token: str, uuid: str) -> str:
    r = requests.get(f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{uuid}/client-secret",
                     headers=h(token), timeout=10)
    r.raise_for_status()
    return r.json().get("value", "")


def create_user(token: str, username: str, password: str,
                first: str, last: str, email: str) -> None:
    r = requests.post(f"{KEYCLOAK_URL}/admin/realms/{REALM}/users", headers=h(token),
                      timeout=10, json={
        "username": username, "enabled": True, "emailVerified": True,
        "firstName": first, "lastName": last, "email": email,
        "requiredActions": [],
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    if r.status_code == 409:
        print(f"  user '{username}' already exists.")
    else:
        r.raise_for_status()
        print(f"  user '{username}' created.")


def main() -> None:
    wait_for_keycloak()
    token = get_admin_token()

    # ── [1] Realm ─────────────────────────────────────────────────
    print("\n[1] Creating realm...")
    create_realm(token)

    # ── [2] Client scopes ────────────────────────────────────────
    print("\n[2] Creating client scopes...")
    for name, desc in CUSTOM_SCOPES:
        create_client_scope(token, name, desc)
    token = get_admin_token()
    scope_map = get_scope_map(token)

    # ── [3] Clients ──────────────────────────────────────────────
    print("\n[3] Creating clients...")

    frontend_uuid = create_client(token, {
        "clientId": "frontend", "publicClient": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:3000/*", "http://localhost:8080/*"],
        "webOrigins": ["+"],
        "attributes": {"pkce.code.challenge.method": "S256"},
    })

    planner_uuid = create_client(token, {
        "clientId": "planner", "publicClient": False,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
    })

    executor_uuid = create_client(token, {
        "clientId": "executor", "publicClient": False,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
    })

    _mcp_uuid = create_client(token, {
        "clientId": "mcp-server", "publicClient": False, "bearerOnly": True,
    })

    # ── [4] Assign optional scopes ────────────────────────────────
    print("\n[4] Assigning optional scopes...")
    all_scope_names = [n for n, _ in CUSTOM_SCOPES]
    for uuid, cid in [(frontend_uuid, "frontend"), (planner_uuid, "planner"),
                      (executor_uuid, "executor")]:
        assign_optional_scopes(token, uuid, cid, scope_map, all_scope_names)
        print(f"  scopes assigned to '{cid}'.")

    # ── [5] Audience mappers ──────────────────────────────────────
    print("\n[5] Adding audience protocol mappers...")
    print("  frontend:")
    add_audience_mapper(token, frontend_uuid, "audience-planner",  "planner",  is_client=True)
    add_audience_mapper(token, frontend_uuid, "audience-executor", "executor", is_client=True)
    print("  planner:")
    add_audience_mapper(token, planner_uuid, "audience-executor",     "executor",        is_client=True)
    add_audience_mapper(token, planner_uuid, "audience-mcp-resource", MCP_RESOURCE_URI,  is_client=False)
    print("  executor:")
    add_audience_mapper(token, executor_uuid, "audience-mcp-resource", MCP_RESOURCE_URI, is_client=False)

    # ── [6] Test user ─────────────────────────────────────────────
    print("\n[6] Creating test user alice...")
    create_user(token, "alice", "alice123", "Alice", "Test", "alice@tfm.local")

    # ── [7] Print summary ─────────────────────────────────────────
    token = get_admin_token()
    planner_secret  = get_client_secret(token, planner_uuid)
    executor_secret = get_client_secret(token, executor_uuid)

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"Realm:            {KEYCLOAK_URL}/realms/{REALM}")
    print(f"Admin console:    {KEYCLOAK_URL}/admin")
    print(f"planner secret:   {planner_secret}")
    print(f"executor secret:  {executor_secret}")
    print(f"\nVerify Token Exchange (Paso 1 → 2):")
    print(f"""
  USER_TOKEN=$(curl -s -X POST \\
    {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token \\
    -d 'grant_type=password&client_id=frontend&username=alice&password=alice123' \\
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  curl -s -X POST \\
    {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token \\
    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\
    -d 'client_id=planner&client_secret={planner_secret}' \\
    -d "subject_token=${{USER_TOKEN}}" \\
    -d 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \\
    -d 'scope=read:accounts read:transactions' \\
    | python3 -m json.tool
""")


if __name__ == "__main__":
    main()
