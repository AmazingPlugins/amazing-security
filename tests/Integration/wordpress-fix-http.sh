#!/usr/bin/env bash
# Run only against a disposable Docker WordPress site with a pending off-to-observe proposal.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
proposal_id="${3:?proposal id}"
password="$(openssl rand -hex 20)"

docker run --rm --network amsec-fix-net --volumes-from "$site" \
  -e WORDPRESS_DB_HOST=amsec-fix-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= \
  -e WORDPRESS_DB_NAME="$database" -e AMSEC_TEST_PASSWORD="$password" \
  --user 33:33 wordpress:cli wp eval 'wp_set_password( getenv("AMSEC_TEST_PASSWORD"), 1 );' --quiet >/dev/null

docker exec -i -e AMSEC_TEST_PASSWORD="$password" -e AMSEC_TEST_ID="$proposal_id" -e AMSEC_TEST_SITE="$site" "$site" bash -s <<'INNER'
set -euo pipefail
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT
base="http://$AMSEC_TEST_SITE"
login="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' \
  --data-urlencode 'log=admin' --data-urlencode "pwd=$AMSEC_TEST_PASSWORD" \
  --data-urlencode 'wp-submit=Log In' "$base/wp-login.php")"
test "$login" = 302
page="$(curl -sS -b "$jar" "$base/wp-admin/admin.php?page=amsec-fix-review&proposal=$AMSEC_TEST_ID")"
nonce="$(printf '%s' "$page" | sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' | head -1)"
test -n "$nonce"

submit() {
  curl -sS "$@" -o /dev/null -w '%{http_code}' \
    --data-urlencode 'action=amsec_fix_approve' \
    --data-urlencode "proposal_id=$AMSEC_TEST_ID" \
    --data-urlencode "_wpnonce=$nonce" \
    --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php"
}
anonymous="$(submit)"
forged="$(curl -sS -b "$jar" -o /dev/null -w '%{http_code}' \
  --data-urlencode 'action=amsec_fix_approve' \
  --data-urlencode "proposal_id=$AMSEC_TEST_ID" \
  --data-urlencode '_wpnonce=forged' --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php")"
valid="$(submit -b "$jar")"
replay="$(submit -b "$jar")"
test "$anonymous" = 400
test "$forged" = 403
test "$valid" = 302
test "$replay" = 409

page="$(curl -sS -b "$jar" "$base/wp-admin/admin.php?page=amsec-fix-review&proposal=$AMSEC_TEST_ID")"
nonce="$(printf '%s' "$page" | sed -n 's/.*name="_wpnonce" value="\([^"]*\)".*/\1/p' | head -1)"
test -n "$nonce"
rollback="$(curl -sS -b "$jar" -o /dev/null -w '%{http_code}' \
  --data-urlencode 'action=amsec_fix_rollback' \
  --data-urlencode "proposal_id=$AMSEC_TEST_ID" \
  --data-urlencode "_wpnonce=$nonce" --data-urlencode 'confirm=1' "$base/wp-admin/admin-post.php")"
test "$rollback" = 302
echo "HTTP anonymous=$anonymous forged=$forged valid=$valid replay=$replay rollback=$rollback"
INNER

docker run --rm --network amsec-fix-net --volumes-from "$site" \
  -e WORDPRESS_DB_HOST=amsec-fix-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= \
  -e WORDPRESS_DB_NAME="$database" -e AMSEC_TEST_ID="$proposal_id" \
  --user 33:33 wordpress:cli wp eval \
  '$r=new AmazingPlugins\Security\Fixes\WordPressFixRepository($GLOBALS["wpdb"]); $p=$r->get(getenv("AMSEC_TEST_ID")); if($p->status!=="rolled_back"||get_option("amsec_login_rate_mode")!=="off"||array_column($r->audit($p->id),"event")!==array("applied","rolled_back")) throw new RuntimeException("Unexpected HTTP fix result"); echo "state, mode, and audit passed";' --user=admin
