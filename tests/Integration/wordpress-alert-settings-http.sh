#!/usr/bin/env bash
# Run only on a disposable WordPress Docker site.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
network="${3:?docker network}"
database_host="${4:?database host}"
login="amsec-alert-$(openssl rand -hex 4)"
password="$(openssl rand -hex 16)"
previous="$(docker run --rm --network "$network" --volumes-from "$site" -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" --user 33:33 wordpress:cli wp option get amsec_alerts_enabled --quiet 2>/dev/null || true)"

wp() {
  docker run --rm --network "$network" --volumes-from "$site" \
    -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root \
    -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" \
    -e "AMSEC_TEST_LOGIN=$login" -e "AMSEC_TEST_PASSWORD=$password" \
    --user 33:33 wordpress:cli wp "$@"
}

cleanup() {
  wp user delete "$login" --yes --reassign=1 >/dev/null 2>&1 || true
  if [ -z "$previous" ]; then
    wp option delete amsec_alerts_enabled >/dev/null 2>&1 || true
  else
    wp option update amsec_alerts_enabled "$previous" >/dev/null 2>&1 || true
  fi
}
trap 'status=$?; if [ "$status" -ne 0 ]; then printf "Alert HTTP fixture failed at host line %s (status %s).\n" "$LINENO" "$status" >&2; fi; cleanup' EXIT

docker cp "$(cd "$(dirname "$0")" && pwd)/wordpress-alert-settings-http-setup.php" "$site:/var/www/html/wp-content/amsec-alert-http-setup.php"
wp eval-file /var/www/html/wp-content/amsec-alert-http-setup.php --user=admin --quiet >/dev/null

docker exec -i -e AMSEC_TEST_LOGIN="$login" -e AMSEC_TEST_PASSWORD="$password" -e AMSEC_TEST_SITE="$site" "$site" bash -s <<'INNER'
set -euo pipefail
stage=init
base="http://$AMSEC_TEST_SITE"
cookies="$(mktemp)"
page="$(mktemp)"
trap 'status=$?; if [ "$status" -ne 0 ]; then printf "Alert HTTP request failed at %s (status %s).\n" "$stage" "$status" >&2; fi; rm -f "$cookies" "$page"' EXIT
stage=anonymous
status="$(curl -sS -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_alert_settings' --data-urlencode 'enabled=0' "$base/wp-admin/admin-post.php")"
test "$status" = 400 || test "$status" = 403
stage=login
curl -sS -c "$cookies" -b "$cookies" -L -o /dev/null --data-urlencode "log=$AMSEC_TEST_LOGIN" --data-urlencode "pwd=$AMSEC_TEST_PASSWORD" --data-urlencode 'wp-submit=Log In' "$base/wp-login.php"
stage=page
status="$(curl -sS -b "$cookies" -o "$page" -w '%{http_code}' "$base/wp-admin/admin.php?page=amsec-settings")"
test "$status" = 200
grep -q 'name="action" value="amsec_alert_settings"' "$page"
stage=nonce
nonce="$(sed -n 's/.*name="action" value="amsec_alert_settings"><input type="hidden" name="_wpnonce" value="\([^"]*\)".*/\1/p' "$page" | tail -1)"
test -n "$nonce"
stage=denied
denied="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_alert_settings' --data-urlencode 'enabled=0' --data-urlencode '_wpnonce=invalid' "$base/wp-admin/admin-post.php")"
test "$denied" = 403
stage=invalid
invalid="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_alert_settings' --data-urlencode 'enabled=other' --data-urlencode "_wpnonce=$nonce" "$base/wp-admin/admin-post.php")"
test "$invalid" = 400
stage=saved
saved="$(curl -sS -b "$cookies" -o /dev/null -w '%{http_code}' --data-urlencode 'action=amsec_alert_settings' --data-urlencode 'enabled=0' --data-urlencode "_wpnonce=$nonce" "$base/wp-admin/admin-post.php")"
test "$saved" = 302
printf 'Administrator alert setting HTTP checks: %s/%s/%s\n' "$denied" "$invalid" "$saved"
INNER
test "$(wp option get amsec_alerts_enabled --quiet)" = 0
