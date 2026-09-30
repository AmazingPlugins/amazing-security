#!/usr/bin/env bash
# Only the named disposable Docker site. Requires the Redis drop-in to be active.
set -euo pipefail
id="$(openssl rand -hex 8)"
directory="/var/www/html/wp-content/amsec-cache-test-$id"
fixture="/var/www/html/wp-content/amsec-cache-worker-$id.php"
logs="$(mktemp -d)"
worker_a=''
worker_b=''
wp_worker() {
  docker run --rm --network amsec-next-net --volumes-from amsec-next-wp \
    -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME=wordpress \
    -e "AMSEC_CACHE_TEST_ID=$id" -e "AMSEC_CACHE_TEST_MODE=$1" --user 33:33 wordpress:cli wp eval-file "$fixture"
}
cleanup() {
  docker exec amsec-next-wp touch "$directory/release" >/dev/null 2>&1 || true
  if [ -n "$worker_a" ]; then wait "$worker_a" || true; fi
  if [ -n "$worker_b" ]; then wait "$worker_b" || true; fi
  docker exec amsec-next-wp rm -rf "$directory" "$fixture"
  rm -rf "$logs"
}
trap cleanup EXIT
wait_for() {
  for ((i=0;i<100;i++)); do
    if docker exec amsec-next-wp test -f "$directory/$1"; then return; fi
    sleep 0.1
  done
  printf 'Missing barrier: %s\n' "$1" >&2
  cat "$logs"/* >&2
  return 1
}
docker exec amsec-next-wp mkdir -m 700 "$directory"
docker exec amsec-next-wp chown 33:33 "$directory"
docker cp "$(dirname "$0")/wordpress-persistent-cache-worker.php" "amsec-next-wp:$fixture"
wp_worker seed
wp_worker read
wp_worker a > "$logs/a" 2>&1 & worker_a=$!
wp_worker b > "$logs/b" 2>&1 & worker_b=$!
wait_for ready-a
wait_for ready-b
docker exec amsec-next-wp touch "$directory/go"
wait_for result-a
wait_for result-b
docker exec amsec-next-wp php -r '$a=file_get_contents($argv[1]."/result-a"); $b=file_get_contents($argv[1]."/result-b"); if (!in_array($a,["0","1"],true)||!in_array($b,["0","1"],true)||(int)$a+(int)$b!==1) { exit(1); } echo "Exactly one independent worker owns the live lease.\n";' "$directory"
docker exec amsec-next-wp touch "$directory/release"
wait "$worker_a"; worker_a=''
wait "$worker_b"; worker_b=''
wp_worker after
