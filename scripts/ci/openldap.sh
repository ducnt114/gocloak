#!/bin/sh
# Starts an OpenLDAP server for the LDAP tests: suffix dc=example,dc=org,
# root cn=admin,dc=example,dc=org / secret, on ldap://127.0.0.1:3890.
# ROOT is where slapd is installed (default /, e.g. after apt-get install slapd).
set -eu
ROOT=${ROOT:-}
DIR=${DIR:-$(mktemp -d)}
mkdir -p "$DIR/data"
cat > "$DIR/slapd.conf" <<CONF
include $ROOT/etc/ldap/schema/core.schema
include $ROOT/etc/ldap/schema/cosine.schema
include $ROOT/etc/ldap/schema/inetorgperson.schema
include $ROOT/etc/ldap/schema/nis.schema
modulepath $ROOT/usr/lib/ldap
moduleload back_mdb
pidfile $DIR/slapd.pid
database mdb
suffix "dc=example,dc=org"
rootdn "cn=admin,dc=example,dc=org"
rootpw secret
directory $DIR/data
maxsize 104857600
CONF
"$ROOT/usr/sbin/slapd" -f "$DIR/slapd.conf" -h ldap://127.0.0.1:3890/
echo "slapd started (pid $(cat "$DIR/slapd.pid"))"
