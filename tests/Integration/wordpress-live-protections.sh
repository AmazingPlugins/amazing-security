#!/usr/bin/env bash
# Live protection checks against a local WordPress container (default ironlatch-clean).
# Usage: bash tests/Integration/wordpress-live-protections.sh [container] [base-url] Saves and restores every option it touches.
set -u
C=${1:-ironlatch-clean}; B=${2:-http://127.0.0.1:18890}; T=$(mktemp -d)
wp() { docker exec "$C" wp --allow-root --path=/var/www/html "$@" 2>/dev/null; }
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
OPTS="ironlatch_comment_rate ironlatch_hide_generator ironlatch_hide_discovery_links ironlatch_login_xmlrpc_disabled ironlatch_email_factor ironlatch_login_challenge ironlatch_approve_registrations users_can_register ironlatch_idle_minutes ironlatch_block_agents ironlatch_comment_rate ironlatch_password_require_number ironlatch_password_rules ironlatch_login_confirm"
for o in $OPTS; do echo "$o=$(wp option get $o)" >> "$T/saved"; done
restore() { while IFS='=' read -r o v; do if [ -z "$v" ]; then wp option delete "$o" >/dev/null; else wp option update "$o" "$v" >/dev/null; fi; done < "$T/saved"; wp user delete ironlatchtest --yes >/dev/null; wp user delete ironlatchself --yes >/dev/null; docker exec $C rm -f /var/www/html/wp-content/mu-plugins/zz-ironlatch-mailcap.php; wp option delete ironlatch_test_mail >/dev/null; rm -rf "$T"; }
trap restore EXIT
docker exec $C bash -c 'cat > /var/www/html/wp-content/mu-plugins/zz-ironlatch-mailcap.php <<"PHP"
<?php
// Test-only mail capture; removed by live-protections.sh.
add_filter( "pre_wp_mail", function ( $r, $a ) { update_option( "ironlatch_test_mail", wp_json_encode( $a ), false ); return true; }, 10, 2 );
PHP'
wp option update ironlatch_login_confirm 0 >/dev/null
wp user create ironlatchtest ironlatchtest@example.invalid --role=subscriber --user_pass='Live-test-pass-2026' >/dev/null
login() { # $1 jar, extra form args...
  local jar=$1; shift
  curl -s -c "$jar" -b "$jar" -b 'wordpress_test_cookie=WP%20Cookie%20check' -o "$T/body" -w '%{http_code} %{redirect_url}' \
    --data-urlencode log=ironlatchtest --data-urlencode pwd='Live-test-pass-2026' --data-urlencode testcookie=1 "$@" "$B/wp-login.php"; }

# 1. Version tag and discovery links
wp option update ironlatch_hide_generator 1 >/dev/null; wp option update ironlatch_hide_discovery_links 1 >/dev/null
h=$(curl -s "$B/"); echo "$h" | grep -qi 'name="generator" content="WordPress' && bad "version tag still public" || ok "version tag hidden"
echo "$h" | grep -qi 'EditURI\|wlwmanifest' && bad "discovery links still public" || ok "discovery links removed"

# 2. XML-RPC password sign-in
wp option update ironlatch_login_xmlrpc_disabled 1 >/dev/null
r=$(curl -s -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>ironlatchtest</value></param><param><value>Live-test-pass-2026</value></param></params></methodCall>' "$B/xmlrpc.php")
echo "$r" | grep -q '<name>faultCode</name>' && ok "XML-RPC sign-in refused" || bad "XML-RPC sign-in allowed: ${r:0:120}"
wp option update ironlatch_login_xmlrpc_disabled 0 >/dev/null
r=$(curl -s -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>ironlatchtest</value></param><param><value>Live-test-pass-2026</value></param></params></methodCall>' "$B/xmlrpc.php")
echo "$r" | grep -q 'blogName' && ok "XML-RPC sign-in works again when allowed" || bad "XML-RPC control did not switch back: ${r:0:120}"

# 3. Email sign-in code
wp option update ironlatch_email_factor 1 >/dev/null
first=$(login "$T/j1")
mail=$(wp option get ironlatch_test_mail)
code=$(echo "$mail" | grep -oE '[0-9]{6}' | head -1)
[ -n "$code" ] && ok "email code sent on password step ($first)" || bad "no email code captured ($first)"
wrong=$(login "$T/j1" --data-urlencode ironlatch_email_code=000000)
echo "$wrong" | grep -q 'wp-admin' && bad "wrong email code accepted" || ok "wrong email code refused"
right=$(login "$T/j1" --data-urlencode ironlatch_email_code="$code")
echo "$right" | grep -q '302' && ok "right email code signs in" || bad "right email code refused ($right)"
wp option update ironlatch_email_factor 0 >/dev/null

# 4. Login question
wp option update ironlatch_login_challenge 1 >/dev/null
curl -s -c "$T/j2" "$B/wp-login.php" > "$T/form"
q=$(grep -oE '[0-9]+ \+ [0-9]+' "$T/form" | head -1)
if [ -n "$q" ]; then
  sum=$(( ${q% + *} + ${q#* + } ))
  w=$(login "$T/j2" --data-urlencode ironlatch_login_sum=$((sum+1)))
  echo "$w" | grep -q 'wp-admin' && bad "wrong sum accepted" || ok "wrong sum refused"
  curl -s -c "$T/j3" -b "$T/j3" "$B/wp-login.php" > "$T/form"; q=$(grep -oE '[0-9]+ \+ [0-9]+' "$T/form" | head -1); sum=$(( ${q% + *} + ${q#* + } ))
  r=$(login "$T/j3" --data-urlencode ironlatch_login_sum=$sum)
  echo "$r" | grep -q '302' && ok "right sum signs in" || bad "right sum refused ($r)"
else bad "login question not shown"; fi
wp option update ironlatch_login_challenge 0 >/dev/null

# 5. Registration approval (self sign-up)
wp option update users_can_register 1 >/dev/null; wp option update ironlatch_approve_registrations 1 >/dev/null
curl -s -b 'wordpress_test_cookie=WP%20Cookie%20check' -o /dev/null --data-urlencode user_login=ironlatchself --data-urlencode user_email=ironlatchself@example.invalid "$B/wp-login.php?action=register"
p=$(wp user meta get ironlatchself ironlatch_registration_pending)
[ "$p" = "1" ] && ok "self sign-up held for approval" || bad "self sign-up not held (meta='$p')"
wp user update ironlatchself --user_pass='Live-test-pass-2026' >/dev/null
r=$(curl -s -b 'wordpress_test_cookie=WP%20Cookie%20check' -o "$T/b" -w '%{http_code}' --data-urlencode log=ironlatchself --data-urlencode pwd='Live-test-pass-2026' --data-urlencode testcookie=1 "$B/wp-login.php")
grep -q 'approve' "$T/b" && ok "held account cannot sign in" || bad "held account signed in ($r)"

# 6. Idle logout
wp option update ironlatch_idle_minutes 15 >/dev/null
login "$T/j4" >/dev/null
uid=$(wp user get ironlatchtest --field=ID)
curl -s -b "$T/j4" -o /dev/null "$B/wp-admin/profile.php"
wp user meta update "$uid" ironlatch_last_seen $(( $(date +%s) - 3600 )) >/dev/null
r=$(curl -s -b "$T/j4" -c "$T/j4" -o /dev/null -w '%{http_code} %{redirect_url}' "$B/wp-admin/profile.php")
echo "$r" | grep -q 'wp-login' && ok "idle session signed out ($r)" || bad "idle session kept ($r)"
wp option update ironlatch_idle_minutes 0 >/dev/null

# 7. Blocked user agent
wp option update ironlatch_block_agents 'EvilScanner' >/dev/null
r=$(curl -s -o /dev/null -w '%{http_code}' -A 'EvilScanner/1.0' "$B/")
[ "$r" = "403" ] && ok "listed user agent blocked (403)" || bad "listed user agent got $r"
r=$(curl -s -o /dev/null -w '%{http_code}' "$B/")
[ "$r" = "200" ] && ok "normal visitor still served" || bad "normal visitor got $r"

# 8. Password rules on profile change
wp option update ironlatch_password_require_number 1 >/dev/null
r=$(wp eval '$_POST["pass1"]="onlyletterspassword"; $e=new WP_Error(); $u=(object)array("ID"=>'"$uid"',"user_login"=>"ironlatchtest","user_pass"=>"onlyletterspassword"); do_action_ref_array("user_profile_update_errors", array(&$e, true, &$u)); echo $e->has_errors() ? "refused" : "accepted";')
[ "$r" = "refused" ] && ok "password without a number refused" || bad "password without a number $r"

# 9. Login bot trap: no checkbox, people sign in untouched, a filled hidden field is refused
wp option update ironlatch_login_confirm 1 >/dev/null
f=$(curl -s "$B/wp-login.php")
echo "$f" | grep -q 'type="checkbox" name="ironlatch_login_confirm"' && bad "sign-in checkbox still shown" || ok "no sign-in checkbox on the login form"
echo "$f" | grep -q 'name="ironlatch_lt_note"' && ok "hidden bot field present" || bad "hidden bot field missing"
r=$(login "$T/j5"); echo "$r" | grep -q '302' && ok "person signs in without ticking anything" || bad "plain sign-in refused ($r)"
r=$(login "$T/j6" --data-urlencode ironlatch_lt_note=http://spam.example); echo "$r" | grep -q 'wp-admin' && bad "filled bot field signed in" || ok "filled bot field refused"
wp option update ironlatch_login_confirm 0 >/dev/null

# 10. Comments: one per minute per email, first one allowed (core flood check switched off for this test)
docker exec $C bash -c 'printf "<?php\n// Temporary: core 15 s flood check off so the plugin rule is tested alone.\nadd_filter( \"wp_is_comment_flood\", \"__return_false\", 99 );\nremove_action( \"check_comment_flood\", \"check_comment_flood_db\" );\n" > /var/www/html/wp-content/mu-plugins/zz-ironlatch-noflood.php'
pid=$(wp post create --post_title="ironlatch comment test" --post_status=publish --comment_status=open --porcelain)
wp option update ironlatch_comment_rate 1 >/dev/null; e="guest$RANDOM@example.invalid"
cpost() { curl -s -o /dev/null -w '%{http_code}' --data-urlencode "comment_post_ID=$pid" --data-urlencode author=Guest --data-urlencode "email=$e" --data-urlencode "comment=$1" "$B/wp-comments-post.php"; }
cpost "first guest comment here" >/dev/null; n1=$(wp comment list --post_id=$pid --status=all --format=count)
cpost "second guest comment here" >/dev/null; n2=$(wp comment list --post_id=$pid --status=all --format=count)
[ "$n1" = "1" ] && ok "first guest comment allowed" || bad "first guest comment refused"
[ "$n2" = "1" ] && ok "second comment inside a minute refused" || bad "second comment let through"
wp post delete $pid --force >/dev/null; docker exec $C rm -f /var/www/html/wp-content/mu-plugins/zz-ironlatch-noflood.php

echo "---- $pass passed, $fail failed"
