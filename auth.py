import json
import os
import re

import gssapi
from flask import Flask, make_response, request
from ldap3 import KERBEROS, SASL, Connection, Server

app = Flask(__name__)


def check_env_variables():
    """Check if all required environment variables are set."""
    required_vars = [
        "AD_SERVER",
        "CONFIG_PATH",
        "KEYTAB_PATH",
        "LDAP_SEARCH_BASE",
        "SERVER_PRINCIPAL_NAME",
    ]
    for var in required_vars:
        if not os.getenv(var):
            raise EnvironmentError(f"Required environment variable {var} is not set")


check_env_variables()


def load_acl(path_to_config):
    """Load ACL config file."""
    with open(path_to_config, "r") as config:
        return json.load(config)


acl = load_acl(os.getenv("CONFIG_PATH"))


def extract_url(request_uri):
    """Extract url from request uri."""
    match = re.match(r"^GET\s+(\S+)\s+HTTP/1.1-uri$", request_uri)
    if match:
        return match.group(1)
    return None


def get_entry(url, port):
    if port not in acl:
        return None
    for k, v in acl[port].items():
        if url.startswith(k):
            return v
    return None


def get_authorized_usernames(url, port):
    """Return list of usernames for given url."""
    entry = get_entry(url, port)
    return entry.get("users", []) if entry else []


def get_authorized_group_dns(url, port):
    """Return list of group dns for given url."""
    entry = get_entry(url, port)
    return entry.get("groups", []) if entry else []


@app.route("/auth/", methods=["GET"])
def auth():
    """Authenticate user based on ACL."""
    username = request.headers.get("X-Remote-User")
    request_uri = request.headers.get("X-Request-Uri")
    server_port = request.headers.get("X-Server-Port")
    if not username or not request_uri:
        # Miscofigured nginx
        return make_response("Internal Server Error", 500)

    url = extract_url(request_uri)

    authorized_usernames = get_authorized_usernames(url, server_port)
    authorized_group_dns = get_authorized_group_dns(url, server_port)

    # No additional auth required
    if not authorized_usernames and not authorized_group_dns:
        return make_response("OK", 200)

    # Check if user is authorized
    if username in authorized_usernames:
        return make_response("OK", 200)

    # Check if user belongs to any of authorized groups
    if authorized_group_dns:
        # Use keytab to authenticate
        gssapi.Credentials(
            usage="initiate",
            name=gssapi.Name(
                os.getenv("SERVER_PRINCIPAL_NAME"),
                gssapi.NameType.kerberos_principal,
            ),
            store={"client_keytab": os.getenv("KEYTAB_PATH")},
        )
        # Connect to AD
        server = Server(os.getenv("AD_SERVER"))
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
        conn.bind()
        # Search for user
        conn.search(
            os.getenv("LDAP_SEARCH_BASE"),
            f"(sAMAccountName={username})",
            attributes=["memberOf"],
        )
        if not conn.entries:
            # User not found(Unexpected error)
            return make_response("Access Denied", 401)

        member_of = (
            conn.entries[0].memberOf.values if "memberOf" in conn.entries[0] else []
        )
        if any(
            group_dn in set(member_of)  # Convert to set for efficient lookup
            for group_dn in authorized_group_dns
        ):
            # Group is authorized
            return make_response("OK", 200)

    return make_response("Forbidden", 403)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
