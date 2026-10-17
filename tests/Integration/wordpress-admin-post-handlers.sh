#!/bin/bash
# Posts every plugin form action to admin-post.php without a nonce. A registered handler refuses (4xx);
# an empty 200 means no handler ran, e.g. because the hook was only added on admin_menu.
# Usage: wordpress-admin-post-handlers.sh <site-url> <logged-in-admin-cookie-jar>
set -uo pipefail
base="${1:?site url}"; jar="${2:?cookie jar}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
body="$(mktemp)"; trap 'rm -f "$body"' EXIT
missing=0
for action in $( { grep -rhoE 'name=\\?"action\\?" value=\\?"[a-z_]+' "$root/src" | grep -oE '[a-z_]+$'; grep -rhoE "'action'[[:space:]]*=>[[:space:]]*'amsec_[a-z_]+'" "$root/src" | grep -oE 'amsec_[a-z_]+'; } | sort -u ); do
  status="$(curl -s -b "$jar" -o "$body" -w '%{http_code}' -d "action=$action" "$base/wp-admin/admin-post.php")"
  if [[ "$status" == 200 && "$(wc -c < "$body")" -lt 5 ]]; then echo "No handler: $action"; missing=1; fi
done
[[ "$missing" == 0 ]] && echo "Every plugin admin-post action reached a handler."
exit "$missing"
