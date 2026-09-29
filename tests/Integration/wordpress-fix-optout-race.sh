#!/usr/bin/env bash
# Run only against a disposable Docker WordPress site with MySQL 8 InnoDB.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
network="${3:?docker network}"
database_host="${4:?database host}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"; docker exec "$site" sh -c "rm -f /var/www/html/wp-content/amsec-race.php /var/www/html/wp-content/amsec-race-*.marker /var/www/html/wp-content/amsec-race-*.release" >/dev/null 2>&1 || true' EXIT
docker cp "$script_dir/wordpress-fix-optout-race.php" "$site:/var/www/html/wp-content/amsec-race.php"

wp() {
  docker run --rm --network "$network" --volumes-from "$site" \
    -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root \
    -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" \
    -e "AMSEC_RACE_MODE=${AMSEC_RACE_MODE:-}" -e "AMSEC_RACE_ID=${AMSEC_RACE_ID:-}" \
    -e "AMSEC_RACE_MARKER=${AMSEC_RACE_MARKER:-}" -e "AMSEC_RACE_RELEASE=${AMSEC_RACE_RELEASE:-}" \
    --user 33:33 wordpress:cli wp eval-file wp-content/amsec-race.php --user=admin --quiet
}

wait_marker() {
  local marker="$1"
  for _ in {1..100}; do
    if docker exec "$site" test -f "$marker"; then return 0; fi
    sleep 0.1
  done
  echo 'Timed out waiting for row-lock holder' >&2
  return 1
}

wait_db_lock() {
  local count
  for _ in {1..100}; do
    count="$(docker exec "$database_host" mysql -uroot -N -e 'SELECT COUNT(*) FROM performance_schema.data_lock_waits')"
    if [[ "$count" =~ ^[1-9][0-9]*$ ]]; then return 0; fi
    sleep 0.1
  done
  echo 'Timed out waiting for a second database connection to block on the row lock' >&2
  return 1
}

run_order() {
  local first="$1" second="$2" expected_first="$3" expected_second="$4" assertion="$5"
  local id marker release
  id="$(AMSEC_RACE_MODE=setup wp)"
  marker="/var/www/html/wp-content/amsec-race-$id.marker"
  release="/var/www/html/wp-content/amsec-race-$id.release"
  AMSEC_RACE_MODE="$first" AMSEC_RACE_ID="$id" AMSEC_RACE_MARKER="$marker" AMSEC_RACE_RELEASE="$release" wp >"$scratch/first" 2>&1 &
  local first_pid=$!
  wait_marker "$marker"
  AMSEC_RACE_MODE="$second" AMSEC_RACE_ID="$id" wp >"$scratch/second" 2>&1 &
  local second_pid=$!
  wait_db_lock
  docker exec "$site" touch "$release"
  wait "$first_pid"
  wait "$second_pid"
  test "$(cat "$scratch/first")" = "$expected_first"
  test "$(cat "$scratch/second")" = "$expected_second"
  AMSEC_RACE_MODE="$assertion" AMSEC_RACE_ID="$id" wp
  printf '%s then %s: %s / %s\n' "$first" "$second" "$expected_first" "$expected_second"
}

run_order optout_hold apply 'opt-out committed' unavailable assert_optout_first
run_order apply_hold optout applied 'opt-out committed' assert_approval_first
