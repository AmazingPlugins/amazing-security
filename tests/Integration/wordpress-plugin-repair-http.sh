#!/usr/bin/env bash
# Run only on a disposable WordPress Docker site.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
network="${3:?docker network}"
database_host="${4:?database host}"
id="$(openssl rand -hex 16)"
login="amsec-test-$(openssl rand -hex 4)"
password="$(openssl rand -hex 16)"
backup="$(mktemp)"
cookies="$(mktemp)"
page="$(mktemp)"
backed_up=0

wp() {
  docker run --rm --network "$network" --volumes-from "$site" \
    -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root \
    -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" \
    -e "AMSEC_TEST_ID=$id" -e "AMSEC_TEST_LOGIN=$login" -e "AMSEC_TEST_PASSWORD=$password" \
    --user 33:33 wordpress:cli wp "$@"
}

cleanup() {
  if [ "$backed_up" = 1 ]; then
    docker cp "$backup" "$site:/var/www/html/wp-content/plugins/akismet/akismet.php" >/dev/null 2>&1 || true
    docker exec "$site" chown 33:33 /var/www/html/wp-content/plugins/akismet/akismet.php >/dev/null 2>&1 || true
  fi
  wp user delete "$login" --yes --reassign=1 >/dev/null 2>&1 || true
  wp eval 'delete_option( "amazing_security_integrity_active" );' --user=admin --quiet >/dev/null 2>&1 || true
  rm -f "$backup" "$cookies" "$page"
}
trap cleanup EXIT

docker cp "$site:/var/www/html/wp-content/plugins/akismet/akismet.php" "$backup"
backed_up=1
docker cp "$(cd "$(dirname "$0")" && pwd)/wordpress-plugin-repair-http-setup.php" "$site:/var/www/html/wp-content/amsec-repair-http-setup.php"
wp eval-file /var/www/html/wp-content/amsec-repair-http-setup.php --user=admin --quiet >/dev/null

docker exec -i -e AMSEC_TEST_ID="$id" -e AMSEC_TEST_LOGIN="$login" -e AMSEC_TEST_PASSWORD="$password" -e AMSEC_TEST_SITE="$site" "$site" bash -s <<'INNER'
set -euo pipefail
base="http://$AMSEC_TEST_SITE"
cookies="$(mktemp)"
page="$(mktemp)"
trap 'rm -f "$cookies" "$page"' EXIT
curl -sS -c "$cookies" -b "$cookies" -L -o /dev/null --data-urlencode "log=$AMSEC_TEST_LOGIN" --data-urlencode "pwd=$AMSEC_TEST_PASSWORD" --data-urlencode 'wp-submit=Log In' "$base/wp-login.php"
url="$base/wp-admin/admin.php?page=amsec-repair&finding=$AMSEC_TEST_ID"
status="$(curl -sS -b "$cookies" -o "$page" -w '%{http_code}' "$url")"
test "$status" = 200
grep -q 'Replace this file' "$page"
nonce="$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$page" | tail -1)"
before="$(sed -n 's/.*name="before_sha256" value="\([a-f0-9]*\)".*/\1/p' "$page" | tail -1)"
after="$(sed -n 's/.*name="after_sha256" value="\([a-f0-9]*\)".*/\1/p' "$page" | tail -1)"
test -n "$nonce" && test "${#before}" = 64 && test "${#after}" = 64
denied="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_repair_apply' --data-urlencode "finding_id=$AMSEC_TEST_ID" --data-urlencode "before_sha256=$before" --data-urlencode "after_sha256=$after" --data-urlencode '_wpnonce=invalid' --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php")"
test "$denied" = 403
stale="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_repair_apply' --data-urlencode "finding_id=$AMSEC_TEST_ID" --data-urlencode "before_sha256=$(printf 'a%.0s' {1..64})" --data-urlencode "after_sha256=$after" --data-urlencode "_wpnonce=$nonce" --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php")"
test "$stale" = 409
test "$(sha256sum /var/www/html/wp-content/plugins/akismet/akismet.php | cut -d' ' -f1)" = "$before"
status="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_repair_apply' --data-urlencode "finding_id=$AMSEC_TEST_ID" --data-urlencode "before_sha256=$before" --data-urlencode "after_sha256=$after" --data-urlencode "_wpnonce=$nonce" --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php")"
test "$status" = 302
status="$(curl -sS -b "$cookies" -o "$page" -w '%{http_code}' "$url")"
test "$status" = 200
grep -q 'Roll back this repair' "$page"
rollback_nonce="$(sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' "$page" | tail -1)"
status="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_repair_rollback' --data-urlencode "finding_id=$AMSEC_TEST_ID" --data-urlencode "_wpnonce=$rollback_nonce" "$base/wp-admin/admin-post.php")"
test "$status" = 302
printf 'Administrator HTTP repair and rollback: %s/%s\n' 302 302
INNER
