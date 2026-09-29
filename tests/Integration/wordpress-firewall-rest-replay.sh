#!/usr/bin/env bash
# Run only on a disposable WordPress site with WooCommerce active.
set -euo pipefail

site="${1:?site container}"
database="${2:?database name}"
network="${3:?docker network}"
database_host="${4:?database host}"

wp() {
  docker run --rm --network "$network" --volumes-from "$site" \
    -e "WORDPRESS_DB_HOST=$database_host" -e WORDPRESS_DB_USER=root \
    -e WORDPRESS_DB_PASSWORD= -e "WORDPRESS_DB_NAME=$database" \
    --user 33:33 wordpress:cli wp "$@"
}

wp option delete amsec_rest_observations --quiet >/dev/null 2>&1 || true
docker exec -i -e AMSEC_TEST_SITE="$site" "$site" bash -s <<'INNER'
set -euo pipefail
base="http://$AMSEC_TEST_SITE"
paths=(
  '/wp-json/wp/v2/posts?search=hello'
  '/wp-json/wc/store/v1/products?search=shirt&per_page=10'
  '/wp-json/wc/store/v1/cart'
  '/wp-json/wp/v2/posts?search=How%20does%20UNION%20SELECT%20work'
  '/wp-json/wc/store/v1/products?search=..%2Fdocs'
)
for path in "${paths[@]}"; do
  status="$(curl -sS -o /dev/null -w '%{http_code}' "$base$path")"
  test "$status" = 200
done
printf 'WordPress and WooCommerce public REST: 5/5 responses 200.\n'
INNER
summary="$(wp option get amsec_rest_observations --quiet)"
[[ "$summary" == *'"AS-REST-001"'* && "$summary" == *'"AS-REST-002"'* ]]
[[ "$summary" != *'UNION SELECT'* && "$summary" != *'../docs'* ]]
printf 'Both suspicious-looking benign searches were observed without blocking; stored data contains only rule counts and times.\n'
