#!/bin/bash
set -euo pipefail
umask 077
base="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
preview="${1:?Pass the exact private ZIP path}"
evidence="${2:?Pass a private evidence directory outside the webroot}"
mkdir -p "$evidence"
preview="$(cd "$(dirname "$preview")" && pwd)/$(basename "$preview")"
for pair in 'amsec-next-wp wordpress 66' 'amsec-next-wp69 wordpress69 69'; do
 read -r site db tag <<< "$pair"
 wp() { docker run --rm --network amsec-next-net --volumes-from "$site" -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME="$db" --user 33:33 wordpress:cli wp "$@"; }
 wp_fixture() {
  local fixture="$1"; shift
  docker run --rm --network amsec-next-net --volumes-from "$site" --mount "type=bind,source=$fixture,target=/tmp/amsec-feature-fixture.php,readonly" --mount "type=bind,source=$base/tests/Fixtures/FileScan/corpus.json,target=/tmp/amsec-rule-fixtures.json,readonly" -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME="$db" --user 33:33 wordpress:cli wp eval-file /tmp/amsec-feature-fixture.php "$@"
 }
 backup=$(mktemp /private/tmp/amsec-activity-db.XXXXXX)
 docker exec amsec-next-db mysqldump -uroot "$db" > "$backup"
 # Record dependency directories that this task must remove after restoration.
 created=()
 for slug in woocommerce contact-form-7 classic-editor; do
  if ! docker exec "$site" test -d "/var/www/html/wp-content/plugins/$slug"; then created+=("$slug"); fi
 done
 restore() { docker exec -i amsec-next-db mysql -uroot "$db" < "$backup"; rm -f "$backup"; for slug in "${created[@]}"; do docker exec "$site" rm -rf "/var/www/html/wp-content/plugins/$slug"; done; docker exec "$site" rm -f /var/www/html/wp-content/amsec-activity-test.php /var/www/html/wp-content/amsec-activity-preview.zip /var/www/html/wp-content/amsec-firstwrites.php /var/www/html/wp-content/amsec-sessions-test.php /var/www/html/wp-content/amsec-common-frontend.php /var/www/html/wp-content/amsec-incident-test.php /var/www/html/wp-content/amsec-permissions-test.php /var/www/html/wp-content/amsec-required-totp-test.php /var/www/html/wp-content/amsec-baseline-test.php /var/www/html/wp-content/amsec-bots-test.php /var/www/html/wp-content/amsec-digest-test.php /tmp/amsec-rule-fixtures.json /tmp/amsec-indirect-test.php /tmp/amsec-expanded-rule-corpus.php; }
 trap restore EXIT
 docker cp "$preview" "$site:/var/www/html/wp-content/amsec-activity-preview.zip"
 wp plugin install /var/www/html/wp-content/amsec-activity-preview.zip --force --activate
 if docker exec "$site" test -d /var/www/html/wp-content/plugins/woocommerce; then wp plugin activate woocommerce; else wp plugin install woocommerce --version=9.4.3 --activate; fi
 if docker exec "$site" test -d /var/www/html/wp-content/plugins/contact-form-7; then wp plugin activate contact-form-7; else wp plugin install contact-form-7 --version=6.0.6 --activate; fi
 if docker exec "$site" test -d /var/www/html/wp-content/plugins/classic-editor; then wp plugin activate classic-editor; else wp plugin install classic-editor --activate; fi
 wp eval 'AmazingPlugins\Security\Activity\ActivityTables::install();'
 docker cp "$base/tests/Integration/wordpress-activity.php" "$site:/var/www/html/wp-content/amsec-activity-test.php"
 docker cp "$base/tests/Integration/wordpress-activity-firstwrites.php" "$site:/var/www/html/wp-content/amsec-firstwrites.php"
 wp eval-file /var/www/html/wp-content/amsec-firstwrites.php --user=admin
 docker cp "$base/tests/Integration/wordpress-sessions.php" "$site:/var/www/html/wp-content/amsec-sessions-test.php"
 wp eval-file /var/www/html/wp-content/amsec-sessions-test.php --user=admin
 docker cp "$base/tests/Integration/wordpress-incident.php" "$site:/var/www/html/wp-content/amsec-incident-test.php"
 wp eval-file /var/www/html/wp-content/amsec-incident-test.php --user=admin > "$evidence/incident-result$tag.log"
 docker cp "$base/tests/Integration/wordpress-permissions.php" "$site:/var/www/html/wp-content/amsec-permissions-test.php"
 wp eval-file /var/www/html/wp-content/amsec-permissions-test.php --user=admin > "$evidence/permissions-result$tag.log"
 docker cp "$base/tests/Integration/wordpress-required-totp.php" "$site:/var/www/html/wp-content/amsec-required-totp-test.php"
 wp eval-file /var/www/html/wp-content/amsec-required-totp-test.php --user=admin > "$evidence/required-totp-result$tag.log"
 docker cp "$base/tests/Integration/wordpress-baseline.php" "$site:/var/www/html/wp-content/amsec-baseline-test.php"
 wp eval-file /var/www/html/wp-content/amsec-baseline-test.php --user=admin > "$evidence/baseline-result$tag.log"
 docker cp "$base/tests/Integration/wordpress-bots.php" "$site:/var/www/html/wp-content/amsec-bots-test.php"
 wp eval-file /var/www/html/wp-content/amsec-bots-test.php --user=admin > "$evidence/bots-result$tag.log"
 docker cp "$base/tests/Integration/wordpress-digest.php" "$site:/var/www/html/wp-content/amsec-digest-test.php"
 wp eval-file /var/www/html/wp-content/amsec-digest-test.php --user=admin > "$evidence/digest-result$tag.log"
 wp_fixture "$base/tests/Integration/wordpress-content.php" --user=admin > "$evidence/content-result$tag.log"
 wp_fixture "$base/tests/Integration/wordpress-indirect-detection.php" --user=admin > "$evidence/indirect-result$tag.json"
 wp_fixture "$base/tests/Integration/wordpress-expanded-rule-corpus.php" --user=admin > "$evidence/expanded-corpus$tag.json"
 wp eval-file /var/www/html/wp-content/amsec-activity-test.php --user=admin > "$evidence/activity-result$tag.json"
 # Real plugin lifecycle calls run in separate WordPress processes.
 wp plugin deactivate classic-editor
 wp plugin activate classic-editor
 wp eval ' $r=new AmazingPlugins\Security\Activity\ActivityRepository($GLOBALS["wpdb"]);foreach(["plugin_activated","plugin_deactivated"] as $event){if(!$r->page(1,$event)){throw new RuntimeException("Plugin lifecycle event absent.");}} echo "Real plugin activation/deactivation recorded.\n";'
 docker cp "$base/tests/Integration/wordpress-common-frontend.php" "$site:/var/www/html/wp-content/amsec-common-frontend.php"
 page=$(wp eval-file /var/www/html/wp-content/amsec-common-frontend.php --user=admin)
 docker exec "$site" curl -fsSL --max-time 30 "http://localhost/?page_id=$page" > "$evidence/common-frontend$tag.html"
 python3 - "$tag" "$evidence" <<'PYTEST'
import sys
from pathlib import Path
s=(Path(sys.argv[2])/('common-frontend'+sys.argv[1]+'.html')).read_text()
assert 'wpcf7-form' in s and 'Amazing Security dummy product' in s and 'add-to-cart' in s
assert 'Fatal error' not in s
print('Real Apache HTTP page renders Contact Form 7 and WooCommerce product/cart controls.')
PYTEST
 wp plugin check amazing-security --format=table
 docker exec "$site" sh -c 'find /var/www/html/wp-content/plugins/amazing-security -name "*.php" -exec php -l {} \;' > "$evidence/php-lint$tag.log"
 restore
 trap - EXIT
done
