<?php
// Only on named disposable databases, after installing the exact private ZIP.
if ( ! defined('WP_CLI') || ! WP_CLI || 'amsec-next-db' !== DB_HOST || ! in_array(DB_NAME,['wordpress','wordpress69'],true) ) { exit(1); }
use AmazingPlugins\Security\Activity\ActivityEvent;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Activity\ActivityPage;
global $wpdb;
$r=new ActivityRepository($wpdb);
$table=$wpdb->prefix.'amsec_activity';
$wpdb->query("DELETE FROM {$table}");
update_option('amsec_activity_enabled','1',false);
wp_set_current_user(1);
$id=wp_insert_user(['user_login'=>'amsec-activity-fixture-'.bin2hex(random_bytes(4)),'user_pass'=>bin2hex(random_bytes(16)),'role'=>'subscriber']);
if(is_wp_error($id)){throw new RuntimeException('Fixture user creation failed.');}
$user=get_user_by('id',$id);$user->set_role('editor');
$secret=bin2hex(random_bytes(16));wp_set_password($secret,$id);
wp_set_current_user(0);
$ok=wp_signon(['user_login'=>$user->user_login,'user_password'=>$secret,'remember'=>false],false);
if(is_wp_error($ok)){throw new RuntimeException('Normal login failed.');}
$bad=wp_signon(['user_login'=>$user->user_login,'user_password'=>$secret.'bad'],false);
if(!is_wp_error($bad)){throw new RuntimeException('Bad password accepted.');}
wp_set_current_user(1);
update_option('amsec_login_xmlrpc_disabled','activity-fixture');
$rows=$r->page();$events=array_column($rows,'event');
foreach(['login_succeeded','login_failed','user_created','user_role_changed','security_setting_changed'] as $event){if(!in_array($event,$events,true)){throw new RuntimeException('Missing actual event: '.$event);}}
if(str_contains(json_encode($rows),$secret)||str_contains(json_encode($rows),$user->user_login)){throw new RuntimeException('Sensitive login material retained.');}
ob_start();(new ActivityPage())->render();$html=ob_get_clean();if(!str_contains($html,'Security activity')){throw new RuntimeException('Activity view missing.');}
$handler=static fn()=>static function(){throw new RuntimeException('activity_denied');};
add_filter('wp_die_handler',$handler);wp_set_current_user($id);
try{(new ActivityPage())->render();throw new LogicException('Editor saw activity.');}catch(RuntimeException $e){if($e->getMessage()!=='activity_denied'){throw $e;}}finally{remove_filter('wp_die_handler',$handler);wp_set_current_user(1);}
// A missing table must not emit SQL errors or break login; the admin view must show unavailable.
$missing=$table.'_fixture_missing';
$wpdb->query("RENAME TABLE {$table} TO {$missing}");
try {
    $previous=$wpdb->show_errors(true);
    ob_start();$still=wp_signon(['user_login'=>$user->user_login,'user_password'=>$secret],false);$output=ob_get_clean();
    if(is_wp_error($still)||str_contains($output,'database error')){throw new RuntimeException('Activity failure disrupted normal login.');}
    ob_start();(new ActivityPage())->render();$unavailable=ob_get_clean();
    if(!str_contains($unavailable,'storage is unavailable')){throw new RuntimeException('Missing table shown as empty history.');}
    $wpdb->show_errors($previous);
} finally { $wpdb->query("RENAME TABLE {$missing} TO {$table}"); }
// Independent repository admission tests are not affected by per-request hook budget.
$wpdb->query("DELETE FROM {$table} WHERE event='login_failed'");
$accepted=0;for($i=0;$i<105;$i++){if($r->append(new ActivityEvent('login_failed',0,0,'',time()))){$accepted++;}}
if($accepted!==100){throw new RuntimeException('Failed-login quota incorrect.');}
if(!$r->append(new ActivityEvent('user_role_changed',1,$id,'administrator',time()))){throw new RuntimeException('Administrative event starved by login failures.');}
$wpdb->query($wpdb->prepare("INSERT INTO {$table} (event,actor_id,user_id,target,created_at) VALUES (%s,0,0,'',%d)",'login_failed',time()-31*DAY_IN_SECONDS));
$r->cleanup(time());if((int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE created_at<%d",time()-30*DAY_IN_SECONDS))!==0){throw new RuntimeException('Retention cleanup failed.');}
$versions=[];require_once ABSPATH.'wp-admin/includes/plugin.php';
foreach(['woocommerce/woocommerce.php','contact-form-7/wp-contact-form-7.php','classic-editor/classic-editor.php'] as $plugin){if(!is_plugin_active($plugin)){throw new RuntimeException('Common test plugin inactive: '.$plugin);} $versions[$plugin]=get_plugin_data(WP_PLUGIN_DIR.'/'.$plugin)['Version'];}
if(!class_exists('WPCF7_ContactForm')||!str_contains(WPCF7_ContactForm::get_template()->form_html(),'wpcf7-form')){throw new RuntimeException('Contact Form 7 form render failed.');}
if(apply_filters('use_block_editor_for_post_type',true,'post')!==false){throw new RuntimeException('Classic Editor filter not active.');}
$p=new WC_Product_Simple();$p->set_name('Activity test product');$p->set_regular_price('5');$product=$p->save();
WC()->initialize_session();WC()->initialize_cart();if(!WC()->cart->add_to_cart($product)){throw new RuntimeException('WooCommerce cart failed.');}
if(WC()->cart->get_cart_contents_count()!==1){throw new RuntimeException('WooCommerce cart quantity wrong.');}
wp_delete_user($id);if(!in_array('user_deleted',array_column($r->page(),'event'),true)){throw new RuntimeException('User deletion event missing.');}
echo json_encode(['wordpress'=>get_bloginfo('version'),'cli_php'=>PHP_VERSION,'plugins'=>$versions,'checks'=>'real login/user/role/setting hooks; editor access denial; credential redaction; quota; retention; form/editor/cart compatibility'],JSON_PRETTY_PRINT)."\n";
