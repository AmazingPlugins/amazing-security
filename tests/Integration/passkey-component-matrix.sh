#!/usr/bin/env bash
set -euo pipefail
umask 077
base="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
preview="${1:?Exact private ZIP required}"
fixture="${2:?Passkey component fixture required}"
evidence="${3:?Private evidence directory required}"
preview="$(cd "$(dirname "$preview")" && pwd)/$(basename "$preview")"
fixture="$(cd "$(dirname "$fixture")" && pwd)/$(basename "$fixture")"
case "$fixture" in "$base"/tests/Integration/wordpress-passkey-*.php) ;; *) echo 'Unsupported fixture path.' >&2; exit 1;; esac
mkdir -p "$evidence"
for pair in 'amsec-next-wp wordpress 66' 'amsec-next-wp69 wordpress69 69'; do
 read -r site database tag <<< "$pair"
 if docker exec "$site" test -e /var/www/html/wp-content/amsec-passkey-component.zip; then echo 'Refusing pre-existing component ZIP.' >&2; exit 1; fi
 backup=$(mktemp /private/tmp/amsec-passkey-db.XXXXXX)
 docker exec amsec-next-db mysqldump -uroot "$database" > "$backup"
 restore_passkey() { docker exec -i amsec-next-db mysql -uroot "$database" < "$backup"; rm -f "$backup"; docker exec "$site" rm -f /var/www/html/wp-content/amsec-passkey-component.zip; }
 trap restore_passkey EXIT
 docker cp "$preview" "$site:/var/www/html/wp-content/amsec-passkey-component.zip"
 docker run --rm --network amsec-next-net --volumes-from "$site" -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME="$database" --user 33:33 wordpress:cli wp plugin install /var/www/html/wp-content/amsec-passkey-component.zip --force >"$evidence/install$tag.log" 2>&1
 docker run --rm --network amsec-next-net --volumes-from "$site" --mount "type=bind,source=$fixture,target=/tmp/amsec-passkey-fixture.php,readonly" -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME="$database" --user 33:33 wordpress:cli wp eval-file /tmp/amsec-passkey-fixture.php --user=admin > "$evidence/result$tag.log" 2>&1
 cat "$evidence/result$tag.log"
 restore_passkey
 trap - EXIT
done
