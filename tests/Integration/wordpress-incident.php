<?php
if(!defined('WP_CLI')||!WP_CLI||DB_HOST!=='amsec-next-db'||!in_array(DB_NAME,['wordpress','wordpress69'],true)){exit(1);}
use AmazingPlugins\Security\Incident\ResetRequirement;
use AmazingPlugins\Security\Incident\IncidentAction;
ResetRequirement::KEY;
add_filter('pre_wp_mail',static fn()=>true);
wp_set_current_user(1);$password=bin2hex(random_bytes(20));$targetPassword=bin2hex(random_bytes(20));
$actor=wp_insert_user(['user_login'=>'amsec-incident-admin-'.bin2hex(random_bytes(4)),'user_pass'=>$password,'role'=>'administrator']);
$target=wp_insert_user(['user_login'=>'amsec-incident-target-'.bin2hex(random_bytes(4)),'user_pass'=>$targetPassword,'role'=>'subscriber']);
if(is_wp_error($actor)||is_wp_error($target)){throw new RuntimeException('Fixture creation failed.');}
try {
$policy=new ResetRequirement();$actorManager=WP_Session_Tokens::get_instance($actor);$token=$actorManager->create(time()+3600);$other=$actorManager->create(time()+3600);$manager=WP_Session_Tokens::get_instance($target);$targetToken=$manager->create(time()+3600);
wp_set_current_user($actor);$_SERVER['HTTPS']='on';$_SERVER['REQUEST_METHOD']='POST';
$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$token);$_COOKIE[LOGGED_IN_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'logged_in',$token);
$die=static fn()=>static function($m,$t,$a){throw new RuntimeException('denied:'.($a['response']??500));};add_filter('wp_die_handler',$die);
$base=['user_id'=>(string)$target,'password'=>$password,'confirm'=>'1','_wpnonce'=>wp_create_nonce('amsec_incident_reset_'.$target)];
foreach(['nonce'=>['_wpnonce'=>'bad'],'password'=>['password'=>'bad'],'consent'=>['confirm'=>'0'],'zero'=>['user_id'=>'0'],'array'=>['user_id'=>[]],'missing'=>['user_id'=>'99999999'],'own'=>['user_id'=>(string)$actor,'_wpnonce'=>wp_create_nonce('amsec_incident_reset_'.$actor)]] as $name=>$change){$_POST=array_replace($base,$change);$_REQUEST=$_POST;try{(new IncidentAction())->handle();throw new LogicException('Gate accepted '.$name);}catch(RuntimeException $e){if(!str_starts_with($e->getMessage(),'denied:')){throw $e;}}if($policy->required($target)||!$manager->verify($targetToken)){throw new RuntimeException('Gate mutated target.');}}
foreach(['https','cookie','mismatch','role','method'] as $name){$_POST=$base;$_REQUEST=$_POST;if($name==='https'){$_SERVER['HTTPS']='off';}if($name==='cookie'){unset($_COOKIE[SECURE_AUTH_COOKIE]);}if($name==='mismatch'){$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$other);}if($name==='role'){wp_set_current_user($target);}if($name==='method'){$_SERVER['REQUEST_METHOD']='GET';}try{(new IncidentAction())->handle();throw new LogicException('Gate accepted '.$name);}catch(RuntimeException $e){if(!str_starts_with($e->getMessage(),'denied:')){throw $e;}}$_SERVER['HTTPS']='on';$_SERVER['REQUEST_METHOD']='POST';wp_set_current_user($actor);$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$token);}
$denyWrite=static function($check,$id,$key){return $key===ResetRequirement::KEY ? false : $check;};add_filter('update_user_metadata',$denyWrite,10,3);$_POST=$base;$_REQUEST=$_POST;try{(new IncidentAction())->handle();throw new LogicException('Storage failure reported success.');}catch(RuntimeException $e){if($e->getMessage()!=='denied:409'){throw $e;}}finally{remove_filter('update_user_metadata',$denyWrite,10);}if($policy->required($target)||!$manager->verify($targetToken)){throw new RuntimeException('Storage failure mutated session.');}
class AmsecIncidentNoopManager extends WP_Session_Tokens {
 protected function get_sessions(){return ['fixture'=>['login'=>time(),'expiration'=>time()+3600]];}
 protected function get_session($verifier){return ['login'=>time(),'expiration'=>time()+3600];}
 protected function update_session($verifier,$session=null){}
 protected function destroy_other_sessions($verifier){}
 protected function destroy_all_sessions(){}
 public static function drop_sessions(){}
}
$noop=static fn()=>AmsecIncidentNoopManager::class;add_filter('session_token_manager',$noop);try{(new IncidentAction())->handle();throw new LogicException('Partial revocation reported success.');}catch(RuntimeException $e){if($e->getMessage()!=='denied:409'){throw $e;}}finally{remove_filter('session_token_manager',$noop);}if(!$policy->required($target)||!$manager->verify($targetToken)){throw new RuntimeException('Partial failure state incorrect.');}$policy->clear($target);
$redirect=static function(){throw new RuntimeException('redirect');};add_filter('wp_redirect',$redirect);$_POST=$base;$_REQUEST=$_POST;try{(new IncidentAction())->handle();throw new LogicException('No redirect.');}catch(RuntimeException $e){if($e->getMessage()!=='redirect'){throw $e;}}remove_filter('wp_redirect',$redirect);
if(!$policy->required($target)||$manager->get_all()!==[]||!$actorManager->verify($token)){throw new RuntimeException('Containment failed.');}
$user=get_userdata($target);$result=wp_authenticate($user->user_login,$targetPassword);if(!is_wp_error($result)||$result->get_error_code()!=='amsec_reset_required'){throw new RuntimeException('Correct password accepted.');}
$result=wp_authenticate($user->user_login,'wrong');if(!is_wp_error($result)||$result->get_error_code()==='amsec_reset_required'){throw new RuntimeException('Reset state disclosed before credentials verified.');}
$app=WP_Application_Passwords::create_new_application_password($target,['name'=>'Dummy incident compatibility']);if(is_wp_error($app)){throw new RuntimeException('Application password fixture failed.');}
$api=static fn()=>true;add_filter('application_password_is_api_request',$api);$result=wp_authenticate($user->user_login,$app[0]);remove_filter('application_password_is_api_request',$api);if(!$result instanceof WP_User){throw new RuntimeException('Incident requirement blocked an application password.');}
wp_update_user(['ID'=>$target,'display_name'=>'Unrelated change']);if(!$policy->required($target)){throw new RuntimeException('Unrelated profile update cleared requirement.');}
$newPassword=bin2hex(random_bytes(20));reset_password(get_userdata($target),$newPassword);if($policy->required($target)||is_wp_error(wp_authenticate($user->user_login,$newPassword))){throw new RuntimeException('Native reset recovery failed.');}
$policy->requireReset($target);wp_update_user(['ID'=>$target,'user_pass'=>bin2hex(random_bytes(20))]);if($policy->required($target)){throw new RuntimeException('Native profile recovery failed.');}
$policy->requireReset($target);WP_CLI::runcommand('amazing-security accounts clear-reset '.$target,['return'=>true,'launch'=>false]);if($policy->required($target)){throw new RuntimeException('CLI recovery failed.');}
$_GET=['user_id'=>(string)$target];ob_start();(new AmazingPlugins\Security\Incident\IncidentPage())->render();$html=ob_get_clean();if(!str_contains($html,'amsec_incident_reset')||str_contains($html,$password)||str_contains($html,$token)){throw new RuntimeException('Incident page safety failed.');}
$r=new AmazingPlugins\Security\Activity\ActivityRepository($GLOBALS['wpdb']);foreach(['password_reset_required','password_reset_cleared'] as $event){if(!$r->page(1,$event)){throw new RuntimeException('Incident event absent.');}}
remove_filter('wp_die_handler',$die);
echo "Incident action authorization, revocation, credential denial and native recovery passed.\n";
} finally {wp_set_current_user(1);$_COOKIE=[];wp_delete_user($actor);wp_delete_user($target);}
