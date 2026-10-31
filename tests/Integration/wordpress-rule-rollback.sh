#!/bin/bash
set -euo pipefail
umask 077
previous="${1:?Pass the verified predecessor F30 ZIP}"
current="${2:?Pass the exact current ZIP}"
evidence="${3:?Pass a private evidence directory}"
mkdir -p "$evidence"
[[ "$(shasum -a 256 "$previous" | awk '{print $1}')" == '98b2eef162b554e3ca62c5bf4d21cf80ed1cf132d182be1834f1552c61066d57' ]] || { echo 'Unexpected predecessor ZIP.' >&2; exit 1; }
site=amsec-next-wp69
wp() { docker run --rm --network amsec-next-net --volumes-from "$site" -e WORDPRESS_DB_HOST=amsec-next-db -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD= -e WORDPRESS_DB_NAME=wordpress69 --user 33:33 wordpress:cli wp "$@"; }
wp eval 'if(DB_HOST!=="amsec-next-db"||DB_NAME!=="wordpress69"){throw new RuntimeException("Disposable database required.");}'
backup=$(mktemp /private/tmp/amsec-rule-rollback-db.XXXXXX)
docker exec amsec-next-db mysqldump -uroot wordpress69 > "$backup"
docker cp "$current" "$site:/var/www/html/wp-content/amsec-rule-forward.zip"
restore() {
 docker exec -i amsec-next-db mysql -uroot wordpress69 < "$backup"
 wp plugin install /var/www/html/wp-content/amsec-rule-forward.zip --force --activate > "$evidence/rollback-cleanup.log" 2>&1
 docker exec "$site" rm -f /var/www/html/wp-content/amsec-rule-forward.zip /var/www/html/wp-content/amsec-rule-previous.zip
 rm -f "$backup"
}
trap restore EXIT
wp eval '$c=new AmazingPlugins\Security\Content\ContentCursor(str_repeat("a",32),1,0,time(),hash("sha256","rollback-fixture"));$c->phase="done";$c->after=0;$c->processed=1;$c->finished=true;$c->finishedAt=time();$c->findings=[["kind"=>"post","id"=>1,"rule"=>"AS-HTML-001","line"=>1,"version"=>"2026.09.30.1","tested_at"=>time()]];$report=$c->toArray();$raw=wp_json_encode(["version"=>1,"active"=>$report,"previous"=>$report,"complete"=>$report]);update_option("amsec_content_state",$raw,false);update_option("amsec_rule_rollback_fixture_hash",hash("sha256",$raw),false);echo "Prepared synthetic redacted historical report fixture.\n";' > "$evidence/rollback-result.log"
docker cp "$previous" "$site:/var/www/html/wp-content/amsec-rule-previous.zip"
wp plugin install /var/www/html/wp-content/amsec-rule-previous.zip --force --activate >> "$evidence/rollback-result.log" 2>&1
wp eval 'if(class_exists(AmazingPlugins\Security\Rules\RuleCatalog::class)){throw new RuntimeException("Predecessor code was not installed.");}$raw=get_option("amsec_content_state");$s=(new AmazingPlugins\Security\Content\WordPressContentService())->create()->status();if(hash("sha256",$raw)!==get_option("amsec_rule_rollback_fixture_hash")||($s["complete"]["findings"][0]["version"]??null)!=="2026.09.30.1"){throw new RuntimeException("Rollback changed historical provenance.");}echo "Verified F30 predecessor and unchanged historical report.\n";' >> "$evidence/rollback-result.log"
wp plugin install /var/www/html/wp-content/amsec-rule-forward.zip --force --activate >> "$evidence/rollback-result.log" 2>&1
wp eval '$p=(new AmazingPlugins\Security\Rules\RuleCatalog(dirname(AMSEC_SECURITY_SCANNER_FILE)))->status(time());if(in_array("unknown",array_column($p,"status"),true)||hash("sha256",get_option("amsec_content_state"))!==get_option("amsec_rule_rollback_fixture_hash")){throw new RuntimeException("Forward install failed source verification or changed historical report.");}echo "Forward reinstall verified; retained finding versions remain historical. No future-schema downgrade claim.\n";' >> "$evidence/rollback-result.log"
