#!/usr/bin/env bash
# One-shot setup for the xinliqiu encrypted-object store.
# Requires: node 18+, python3, a Cloudflare account, and `npx wrangler login`.
#
# Usage:
#   ./setup.sh                  provision bucket + database, migrate, mint token
#   ./setup.sh migrate          apply pending migrations to the remote database
#   ./setup.sh migrate --local  apply pending migrations to the local database
#
# Migrations are tracked in the xinliqiu_migrations table and applied in
# filename order. Deploys that were migrated by hand before tracking existed
# are baselined by inspecting the live schema, so 0002's ALTER is never
# replayed onto a database that already has the seq column.
set -euo pipefail
cd "$(dirname "$0")"

DB_NAME="${XINLIQIU_D1_NAME:-xinliqiu-index}"
WRANGLER="${WRANGLER:-npx wrangler}"
TARGET="--remote"
MIGRATE_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    migrate) MIGRATE_ONLY=1 ;;
    --remote) TARGET="--remote" ;;
    --local) TARGET="--local" ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

fail() { printf '\n!! %s\n' "$1" >&2; exit 1; }

command -v node >/dev/null 2>&1 || fail "node 18+ is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

d1_command() {
  # shellcheck disable=SC2086
  $WRANGLER d1 execute "$DB_NAME" "$TARGET" --json --command "$1"
}

d1_file() {
  # shellcheck disable=SC2086
  $WRANGLER d1 execute "$DB_NAME" "$TARGET" --file="$1"
}

d1_query() {
  d1_command "$1" | python3 -c '
import json, sys
text = sys.stdin.read()
try:
    data = json.loads(text)
except json.JSONDecodeError:
    start = text.find("[")
    data = json.loads(text[start:]) if start >= 0 else []
rows = data[0].get("results", []) if isinstance(data, list) and data else []
for row in rows:
    print("\t".join(str(v) for v in row.values()))
'
}

object_table_exists() {
  d1_command "SELECT 1 FROM objects LIMIT 0" >/dev/null 2>&1
}

object_column_exists() {
  d1_command "SELECT $1 FROM objects LIMIT 0" >/dev/null 2>&1
}

migration_recorded() {
  d1_query "SELECT name FROM xinliqiu_migrations WHERE name = '$1'" | grep -q '^'
}

record_migration() {
  d1_command "INSERT INTO xinliqiu_migrations (name, applied_at) VALUES ('$1', $(date +%s))" >/dev/null
}

apply_storage_contract() {
  # ADD COLUMN has no portable IF NOT EXISTS form in SQLite. Handle the two
  # non-repeatable statements here, then run the idempotent remainder even if
  # an older runner already recorded 0003 after only its ALTERs completed.
  object_column_exists device_key \
    || d1_command "ALTER TABLE objects ADD COLUMN device_key TEXT" >/dev/null
  object_column_exists encryption \
    || d1_command "ALTER TABLE objects ADD COLUMN encryption TEXT" >/dev/null

  local remainder status
  # BSD/macOS mktemp only substitutes a template whose trailing characters are
  # X's, so the .sql suffix must be added after substitution.
  local tmpdir=${TMPDIR:-/tmp}
  tmpdir=${tmpdir%/}
  remainder=$(mktemp "$tmpdir/xinliqiu-0003.XXXXXX").sql
  sed \
    -e '/^ALTER TABLE objects ADD COLUMN device_key TEXT;$/d' \
    -e '/^ALTER TABLE objects ADD COLUMN encryption TEXT;$/d' \
    migrations/0003_storage_contract.sql >"$remainder"
  if d1_file "$remainder" >/dev/null; then
    status=0
  else
    status=$?
  fi
  rm -f "$remainder"
  return "$status"
}

apply_migrations() {
  echo "==> applying tracked migrations ($TARGET)"
  d1_command "CREATE TABLE IF NOT EXISTS xinliqiu_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)" >/dev/null

  # Baseline hand-migrated deploys: mark a migration applied only when the
  # schema proves it already ran. Fresh databases record nothing here.
  if object_table_exists; then
    migration_recorded "0001_init.sql" || record_migration "0001_init.sql"
    # 0002's only non-repeatable statement is ALTER TABLE ... ADD COLUMN seq.
    # Once the column exists the migration is baselined; its remaining
    # statements are repeated idempotently by 0003, so a hand-applied or
    # half-applied 0002 still converges instead of failing on the ALTER.
    if object_column_exists seq; then
      migration_recorded "0002_sync.sql" || record_migration "0002_sync.sql"
    fi
  fi

  local file name
  for file in $(ls migrations/*.sql | sort); do
    name=$(basename "$file")
    if migration_recorded "$name"; then
      if [ "$name" = "0003_storage_contract.sql" ]; then
        echo "    $name already applied; verifying storage contract"
        apply_storage_contract
      else
        echo "    $name already applied"
      fi
      continue
    fi
    echo "    applying $name"
    if [ "$name" = "0003_storage_contract.sql" ]; then
      apply_storage_contract
    else
      d1_file "$file" >/dev/null
    fi
    record_migration "$name"
  done
}

if [ "$MIGRATE_ONLY" = "1" ]; then
  if [ "$TARGET" = "--remote" ]; then
    $WRANGLER whoami >/dev/null 2>&1 || fail "not logged in. Run: npx wrangler login"
  fi
  apply_migrations
  echo "==> migrations complete"
  exit 0
fi

if ! $WRANGLER whoami >/dev/null 2>&1; then
  fail "not logged in. Run: npx wrangler login"
fi

echo "==> installing wrangler"
npm install --silent

echo "==> ensuring R2 bucket"
if ! $WRANGLER r2 bucket list 2>/dev/null | grep -q 'xinliqiu-objects'; then
  $WRANGLER r2 bucket create xinliqiu-objects
else
  echo "    bucket already exists"
fi

echo "==> resolving D1 database"
DB_ID=""
# Try to create; if it already exists, fall back to `d1 list`.
CREATE_OUT=$($WRANGLER d1 create "$DB_NAME" 2>&1 || true)
DB_ID=$(printf '%s' "$CREATE_OUT" | sed -n 's/.*database_id = "\([^"]*\)".*/\1/p' | head -1)
if [ -z "${DB_ID:-}" ]; then
  DB_ID=$($WRANGLER d1 list --json 2>/dev/null \
    | python3 -c 'import json,sys
rows=json.load(sys.stdin)
for r in rows:
    if r.get("name")=="'"$DB_NAME"'":
        print(r.get("uuid") or r.get("database_id") or "")
        break' 2>/dev/null || true)
fi
[ -n "${DB_ID:-}" ] || fail "could not determine the D1 database id. Create it with 'npx wrangler d1 create $DB_NAME' and paste the id into wrangler.toml."

echo "==> writing database_id into wrangler.toml"
python3 - "$DB_ID" <<'PY'
import re, sys
path = 'wrangler.toml'
text = open(path, encoding='utf-8').read()
text = re.sub(r'database_id = "[^"]*"', 'database_id = "%s"' % sys.argv[1], text)
open(path, 'w', encoding='utf-8').write(text)
print('    database_id =', sys.argv[1])
PY

apply_migrations

echo "==> generating a bearer token"
TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
printf '%s' "$TOKEN" | $WRANGLER secret put XINLIQIU_TOKEN >/dev/null

cat <<MSG

Done. Next steps:

  1. deploy:            npm run deploy
  2. copy the URL wrangler prints, e.g. https://xinliqiu-store.<subdomain>.workers.dev
  3. export in your client environment:

       XINLIQIU_STORE_URL=<that url>
       XINLIQIU_STORE_TOKEN=$TOKEN

     then pass --store cloudflare to sync.

  4. verify:  curl -H "Authorization: Bearer $TOKEN" <that url>/inventory

Keep the token secret. Rotate it any time with: npx wrangler secret put XINLIQIU_TOKEN
Later schema updates: ./setup.sh migrate --remote
MSG
