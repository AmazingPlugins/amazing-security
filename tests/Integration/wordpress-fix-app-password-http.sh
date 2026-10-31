#!/usr/bin/env bash
# Run only against a disposable Docker WordPress site with a test-only MU plugin
# that enables application passwords on local HTTP.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
network="${3:?docker network}"
database_host="${4:?database host}"
fixture="$(cd "$(dirname "$0")" && pwd)/app-password-rest-harness.php"
docker cp "$fixture" "$site:/var/www/html/wp-content/mu-plugins/amsec-test-approval-route.php"
cleanup() {
  docker exec "$site" rm -f /var/www/html/wp-content/mu-plugins/amsec-test-approval-route.php >/dev/null
  if [ -n "${app_password_id:-}" ]; then
    AMSEC_APP_ID="$app_password_id" wp eval 'WP_Application_Passwords::delete_application_password( 1, getenv( "AMSEC_APP_ID" ) );' --user=admin --quiet >/dev/null
  fi
}
trap cleanup EXIT

wp() {
  docker run --rm --network "$network" --volumes-from "$site" \
    -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root \
    -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" \
    -e "AMSEC_TEST_ID=${AMSEC_TEST_ID:-}" \
    -e "AMSEC_APP_ID=${AMSEC_APP_ID:-}" \
    --user 33:33 wordpress:cli wp "$@"
}

proposal_id="$(wp eval '
  ( new AmazingPlugins\Security\Mcp\McpPreferences( new AmazingPlugins\Security\Integrity\WordPressOptions() ) )->setEnabled( true );
  delete_option( "amsec_login_rate_mode" );
  $id = bin2hex( random_bytes( 16 ) );
  $now = time();
  $proposal = new AmazingPlugins\Security\Fixes\FixProposal( $id, str_repeat( "a", 32 ), "login-rate-observe", "off", "observe", random_int( 1000, 1000000 ), $now, $now + 900 );
  if ( ! ( new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS["wpdb"] ) )->create( $proposal ) ) { throw new RuntimeException( "Proposal setup failed" ); }
  echo $id;
' --user=admin --quiet)"
app_result="$(wp eval '
  $result = WP_Application_Passwords::create_new_application_password( 1, array( "name" => "AmSec Security Scanner approval gate test " . bin2hex( random_bytes( 4 ) ) ) );
  if ( is_wp_error( $result ) ) { throw new RuntimeException( $result->get_error_message() ); }
  echo $result[1]["uuid"] . "|" . $result[0];
' --user=admin --quiet)"
app_password_id="${app_result%%|*}"
app_password="${app_result#*|}"

docker exec -i -e AMSEC_TEST_ID="$proposal_id" -e AMSEC_TEST_APP_PASSWORD="$app_password" -e AMSEC_TEST_SITE="$site" "$site" bash -s <<'INNER'
set -euo pipefail
base="http://$AMSEC_TEST_SITE"
rest="$(curl -sS -u "admin:$AMSEC_TEST_APP_PASSWORD" -o /dev/null -w '%{http_code}' "$base/wp-json/wp/v2/users/me")"
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
approval="$(curl -sS -u "admin:$AMSEC_TEST_APP_PASSWORD" -o "$response_file" -w '%{http_code}' \
  --data-urlencode "proposal_id=$AMSEC_TEST_ID" \
  --data-urlencode '_wpnonce=test-only' \
  --data-urlencode 'confirm=1' "$base/wp-json/amsec-test/v1/approve")"
test "$rest" = 200
test "$approval" = 403
grep -q 'current administrator session is required' "$response_file"
printf 'Application password: REST=%s approval=%s\n' "$rest" "$approval"
INNER

AMSEC_TEST_ID="$proposal_id" wp eval '
  $repo = new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS["wpdb"] );
  $id = getenv( "AMSEC_TEST_ID" );
  $proposal = $repo->get( $id );
  if ( null === $proposal || "pending" !== $proposal->status || "off" !== get_option( "amsec_login_rate_mode", "off" ) || array() !== $repo->audit( $id ) ) {
    throw new RuntimeException( "Application password changed proposal, setting, or audit" );
  }
  echo "Proposal, setting, and audit unchanged\n";
' --user=admin
