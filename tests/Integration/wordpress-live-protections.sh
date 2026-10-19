#!/usr/bin/env bash
# Live protection checks against a local WordPress container (default amsec-clean).
# Usage: bash tests/Integration/wordpress-live-protections.sh [container] [base-url] Saves and restores every option it touches.
set -u
C=${1:-amsec-clean}; B=${2:-http://127.0.0.1:18890}; T=$(mktemp -d)
wp() { docker exec "$C" wp --allow-root --path=/var/www/html "$@" 2>/dev/null; }
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
OPTS="amsec_comment_rate amsec_hide_generator amsec_hide_discovery_links amsec_login_xmlrpc_disabled amsec_email_factor amsec_login_challenge amsec_approve_registrations users_can_register amsec_idle_minutes amsec_block_agents amsec_comment_rate amsec_password_require_number amsec_password_rules amsec_login_confirm"
for o in $OPTS; do echo "$o=$(wp option get $o)" >> "$T/saved"; done
restore() { while IFS='=' read -r o v; do if [ -z "$v" ]; then wp option delete "$o" >/dev/null; else wp option update "$o" "$v" >/dev/null; fi; done < "$T/saved"; wp user delete amsectest --yes >/dev/null; wp user delete amsecself --yes >/dev/null; docker exec $C rm -f /var/www/html/wp-content/mu-plugins/zz-amsec-mailcap.php; wp option delete amsec_test_mail >/dev/null; rm -rf "$T"; }
trap restore EXIT
docker exec $C bash -c 'cat > /var/www/html/wp-content/mu-plugins/zz-amsec-mailcap.php <<"PHP"
<?php
// Test-only mail capture; removed by live-protections.sh.
add_filter( "pre_wp_mail", function ( $r, $a ) { update_option( "amsec_test_mail", wp_json_encode( $a ), false ); return true; }, 10, 2 );
PHP'
wp option update amsec_login_confirm 0 >/dev/null
wp user create amsectest amsectest@example.invalid --role=subscriber --user_pass='Live-test-pass-2026' >/dev/null
login() { # $1 jar, extra form args...
  local jar=$1; shift
  curl -s -c "$jar" -b "$jar" -b 'wordpress_test_cookie=WP%20Cookie%20check' -o "$T/body" -w '%{http_code} %{redirect_url}' \
    --data-urlencode log=amsectest --data-urlencode pwd='Live-test-pass-2026' --data-urlencode testcookie=1 "$@" "$B/wp-login.php"; }

# 1. Version tag and discovery links
wp option update amsec_hide_generator 1 >/dev/null; wp option update amsec_hide_discovery_links 1 >/dev/null
h=$(curl -s "$B/"); echo "$h" | grep -qi 'name="generator" content="WordPress' && bad "version tag still public" || ok "version tag hidden"
echo "$h" | grep -qi 'EditURI\|wlwmanifest' && bad "discovery links still public" || ok "discovery links removed"

# 2. XML-RPC password sign-in
wp option update amsec_login_xmlrpc_disabled 1 >/dev/null
r=$(curl -s -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>amsectest</value></param><param><value>Live-test-pass-2026</value></param></params></methodCall>' "$B/xmlrpc.php")
echo "$r" | grep -q '<name>faultCode</name>' && ok "XML-RPC sign-in refused" || bad "XML-RPC sign-in allowed: ${r:0:120}"
wp option update amsec_login_xmlrpc_disabled 0 >/dev/null
r=$(curl -s -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>amsectest</value></param><param><value>Live-test-pass-2026</value></param></params></methodCall>' "$B/xmlrpc.php")
echo "$r" | grep -q 'blogName' && ok "XML-RPC sign-in works again when allowed" || bad "XML-RPC control did not switch back: ${r:0:120}"

# 3. Email sign-in code
wp option update amsec_email_factor 1 >/dev/null
first=$(login "$T/j1")
mail=$(wp option get amsec_test_mail)
code=$(echo "$mail" | grep -oE '[0-9]{6}' | head -1)
[ -n "$code" ] && ok "email code sent on password step ($first)" || bad "no email code captured ($first)"
wrong=$(login "$T/j1" --data-urlencode amsec_email_code=000000)
echo "$wrong" | grep -q 'wp-admin' && bad "wrong email code accepted" || ok "wrong email code refused"
right=$(login "$T/j1" --data-urlencode amsec_email_code="$code")
echo "$right" | grep -q '302' && ok "right email code signs in" || bad "right email code refused ($right)"
wp option update amsec_email_factor 0 >/dev/null

# 4. Login question
wp option update amsec_login_challenge 1 >/dev/null
curl -s -c "$T/j2" "$B/wp-login.php" > "$T/form"
q=$(grep -oE '[0-9]+ \+ [0-9]+' "$T/form" | head -1)
if [ -n "$q" ]; then
  sum=$(( ${q% + *} + ${q#* + } ))
  w=$(login "$T/j2" --data-urlencode amsec_login_sum=$((sum+1)))
  echo "$w" | grep -q 'wp-admin' && bad "wrong sum accepted" || ok "wrong sum refused"
  curl -s -c "$T/j3" -b "$T/j3" "$B/wp-login.php" > "$T/form"; q=$(grep -oE '[0-9]+ \+ [0-9]+' "$T/form" | head -1); sum=$(( ${q% + *} + ${q#* + } ))
  r=$(login "$T/j3" --data-urlencode amsec_login_sum=$sum)
  echo "$r" | grep -q '302' && ok "right sum signs in" || bad "right sum refused ($r)"
else bad "login question not shown"; fi
wp option update amsec_login_challenge 0 >/dev/null

# 5. Registration approval (self sign-up)
wp option update users_can_register 1 >/dev/null; wp option update amsec_approve_registrations 1 >/dev/null
curl -s -b 'wordpress_test_cookie=WP%20Cookie%20check' -o /dev/null --data-urlencode user_login=amsecself --data-urlencode user_email=amsecself@example.invalid "$B/wp-login.php?action=register"
p=$(wp user meta get amsecself amsec_registration_pending)
[ "$p" = "1" ] && ok "self sign-up held for approval" || bad "self sign-up not held (meta='$p')"
wp user update amsecself --user_pass='Live-test-pass-2026' >/dev/null
r=$(curl -s -b 'wordpress_test_cookie=WP%20Cookie%20check' -o "$T/b" -w '%{http_code}' --data-urlencode log=amsecself --data-urlencode pwd='Live-test-pass-2026' --data-urlencode testcookie=1 "$B/wp-login.php")
grep -q 'approve' "$T/b" && ok "held account cannot sign in" || bad "held account signed in ($r)"

# 6. Idle logout
wp option update amsec_idle_minutes 15 >/dev/null
login "$T/j4" >/dev/null
uid=$(wp user get amsectest --field=ID)
curl -s -b "$T/j4" -o /dev/null "$B/wp-admin/profile.php"
wp user meta update "$uid" amsec_last_seen $(( $(date +%s) - 3600 )) >/dev/null
r=$(curl -s -b "$T/j4" -c "$T/j4" -o /dev/null -w '%{http_code} %{redirect_url}' "$B/wp-admin/profile.php")
echo "$r" | grep -q 'wp-login' && ok "idle session signed out ($r)" || bad "idle session kept ($r)"
wp option update amsec_idle_minutes 0 >/dev/null

# 7. Blocked user agent
wp option update amsec_block_agents 'EvilScanner' >/dev/null
r=$(curl -s -o /dev/null -w '%{http_code}' -A 'EvilScanner/1.0' "$B/")
[ "$r" = "403" ] && ok "listed user agent blocked (403)" || bad "listed user agent got $r"
r=$(curl -s -o /dev/null -w '%{http_code}' "$B/")
[ "$r" = "200" ] && ok "normal visitor still served" || bad "normal visitor got $r"

# 8. Password rules on profile change
wp option update amsec_password_require_number 1 >/dev/null
r=$(wp eval '$_POST["pass1"]="onlyletterspassword"; $e=new WP_Error(); $u=(object)array("ID"=>'"$uid"',"user_login"=>"amsectest","user_pass"=>"onlyletterspassword"); do_action_ref_array("user_profile_update_errors", array(&$e, true, &$u)); echo $e->has_errors() ? "refused" : "accepted";')
[ "$r" = "refused" ] && ok "password without a number refused" || bad "password without a number $r"

# 9. Comments: one per minute per email, first one allowed (core flood check switched off for this test)
docker exec $C bash -c 'printf "<?php\n// Temporary: core 15 s flood check off so the plugin rule is tested alone.\nadd_filter( \"wp_is_comment_flood\", \"__return_false\", 99 );\nremove_action( \"check_comment_flood\", \"check_comment_flood_db\" );\n" > /var/www/html/wp-content/mu-plugins/zz-amsec-noflood.php'
pid=$(wp post create --post_title="amsec comment test" --post_status=publish --comment_status=open --porcelain)
wp option update amsec_comment_rate 1 >/dev/null; e="guest$RANDOM@example.invalid"
cpost() { curl -s -o /dev/null -w '%{http_code}' --data-urlencode "comment_post_ID=$pid" --data-urlencode author=Guest --data-urlencode "email=$e" --data-urlencode "comment=$1" "$B/wp-comments-post.php"; }
cpost "first guest comment here" >/dev/null; n1=$(wp comment list --post_id=$pid --status=all --format=count)
cpost "second guest comment here" >/dev/null; n2=$(wp comment list --post_id=$pid --status=all --format=count)
[ "$n1" = "1" ] && ok "first guest comment allowed" || bad "first guest comment refused"
[ "$n2" = "1" ] && ok "second comment inside a minute refused" || bad "second comment let through"
wp post delete $pid --force >/dev/null; docker exec $C rm -f /var/www/html/wp-content/mu-plugins/zz-amsec-noflood.php

echo "---- $pass passed, $fail failed"
