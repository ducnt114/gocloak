#!/usr/bin/env python3
"""Writes the OpenID conformance suite configuration for a gocloak realm.

usage: config.py OP_BASE_URL > config.json

OP_BASE_URL is gocloak's public (https) base URL, e.g. https://localhost:18445.
The realm "oidf" with its user and clients is created by setup.py.
"""
import json
import sys

op = sys.argv[1].rstrip("/")
realm = op + "/realms/oidf"
auth = realm + "/protocol/openid-connect/auth*"


def login(placeholder=False):
    commands = []
    if placeholder:
        # a snapshot of the login page shown again (prompt=login, max_age)
        commands.append(["wait", "xpath", "//*", 10, "Sign in to your account", "update-image-placeholder-optional"])
    commands += [
        ["text", "id", "username", "oidf-user", "optional"],
        ["text", "id", "password", "oidf-password", "optional"],
        ["click", "id", "kc-login", "optional"],
    ]
    return {"task": "Login", "optional": True, "match": realm + "/*", "commands": commands}


complete = {"task": "Verify Complete", "match": "*/test/*/callback*", "commands": [["wait", "id", "submission_complete", 10]]}


def error_page():
    # the error page shown instead of redirecting to an unregistered URI
    return [{"match": auth, "tasks": [{"task": "Expect the redirect URI error page", "match": auth,
                                        "commands": [["wait", "xpath", "//*", 10, "We are sorry", "update-image-placeholder"]]}]}]


config = {
    "alias": "gocloak",
    "description": "gocloak",
    "server": {"discoveryUrl": realm + "/.well-known/openid-configuration"},
    "client": {"client_id": "oidf1", "client_secret": "oidf1-secret"},
    "client_secret_post": {"client_id": "oidf-post", "client_secret": "oidf-post-secret"},
    "client2": {"client_id": "oidf2", "client_secret": "oidf2-secret"},
    "browser": [{"match": auth, "tasks": [login(), complete]}],
    "override": {
        "oidcc-prompt-login": {"browser": [{"match": auth, "tasks": [login(True), complete]}]},
        "oidcc-max-age-1": {"browser": [{"match": auth, "tasks": [login(True), complete]}]},
        "oidcc-ensure-registered-redirect-uri": {"browser": error_page()},
        "oidcc-ensure-redirect-uri-in-authorization-request": {"browser": error_page()},
        "oidcc-redirect-uri-query-added": {"browser": error_page()},
        "oidcc-redirect-uri-query-mismatch": {"browser": error_page()},
    },
}
json.dump(config, sys.stdout, indent=2)
