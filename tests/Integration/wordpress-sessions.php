<?php
if(!defined('WP_CLI')||!WP_CLI||DB_HOST!=='amsec-next-db'||!in_array(DB_NAME,['wordpress','wordpress69'],true)){exit(1);}
use AmazingPlugins\Security\Sessions\SessionAction;
use AmazingPlugins\Security\Sessions\SessionPage;
use AmazingPlugins\Security\Sessions\SessionPolicy;
// First access fails against the preceding ZIP before any fixture mutation.
SessionPolicy::safeRows([]);
wp_set_current_user(1);$password=bin2hex(random_bytes(20));
$actor=wp_insert_user(['user_login'=>'amsec-session-admin-'.bin2hex(random_bytes(4)),'user_pass'=>$password,'role'=>'administrator']);
$target=wp_insert_user(['user_login'=>'amsec-session-target-'.bin2hex(random_bytes(4)),'user_pass'=>bin2hex(random_bytes(20)),'role'=>'subscriber']);
if(is_wp_error($actor)||is_wp_error($target)){throw new RuntimeException('Fixture accounts failed.');}
$manager=WP_Session_Tokens::get_instance($actor);$keep=$manager->create(time()+3600);$other=$manager->create(time()+3600);
$targetManager=WP_Session_Tokens::get_instance($target);$targetToken=$targetManager->create(time()+3600);
$_SERVER['HTTPS']='on';$_SERVER['REQUEST_METHOD']='POST';wp_set_current_user($actor);
$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$keep);
$_COOKIE[LOGGED_IN_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'logged_in',$keep);
$die=static fn()=>static function($message,$title,$args){throw new RuntimeException('denied:'.($args['response']??500));};add_filter('wp_die_handler',$die);
$base=['user_id'=>(string)$target,'password'=>$password,'confirm'=>'1','_wpnonce'=>wp_create_nonce('amsec_sessions_revoke_'.$target)];
$cases=['bad_nonce'=>['_wpnonce'=>'invalid'],'wrong_password'=>['password'=>'wrong'],'no_confirmation'=>['confirm'=>'0'],'unknown_user'=>['user_id'=>'9999999'],'zero_user'=>['user_id'=>'0'],'array_user'=>['user_id'=>['invalid']]];
foreach($cases as $name=>$change){$_POST=array_replace($base,$change);$_REQUEST=$_POST;try{(new SessionAction())->handle();throw new LogicException('Rejected case succeeded: '.$name);}catch(RuntimeException $e){if(!str_starts_with($e->getMessage(),'denied:')){throw $e;}}if(!$targetManager->verify($targetToken)){throw new RuntimeException('Rejected request revoked a session.');}}
foreach(['insecure','no_cookie','subscriber','get','mismatched_cookie'] as $name){$_POST=$base;$_REQUEST=$_POST;
 if($name==='insecure'){$_SERVER['HTTPS']='off';}if($name==='no_cookie'){unset($_COOKIE[SECURE_AUTH_COOKIE]);}if($name==='mismatched_cookie'){$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$other);}if($name==='subscriber'){wp_set_current_user($target);}if($name==='get'){$_SERVER['REQUEST_METHOD']='GET';}
 try{(new SessionAction())->handle();throw new LogicException('Authorization case succeeded: '.$name);}catch(RuntimeException $e){if(!str_starts_with($e->getMessage(),'denied:')){throw $e;}}
 $_SERVER['HTTPS']='on';$_SERVER['REQUEST_METHOD']='POST';wp_set_current_user($actor);$_COOKIE[SECURE_AUTH_COOKIE]=wp_generate_auth_cookie($actor,time()+3600,'secure_auth',$keep);
}
// A custom manager that ignores revocation must produce failure, never success.
class AmsecNoopSessionManager extends WP_Session_Tokens {
    protected function get_sessions(){return ['fixture'=>['login'=>time(),'expiration'=>time()+3600]];}
    protected function get_session($verifier){return ['login'=>time(),'expiration'=>time()+3600];}
    protected function update_session($verifier,$session=null){}
    protected function destroy_other_sessions($verifier){}
    protected function destroy_all_sessions(){}
    public static function drop_sessions(){}
}
$custom=static fn()=>AmsecNoopSessionManager::class;add_filter('session_token_manager',$custom);
try{(new SessionAction())->revoke($target,$actor,$keep);throw new LogicException('Custom no-op revocation accepted.');}catch(RuntimeException $e){if(!str_contains($e->getMessage(),'could not be verified')){throw $e;}}finally{remove_filter('session_token_manager',$custom);}
// Capture the real action's redirect after mutation, before exit.
$redirect=static function($url){throw new RuntimeException('redirect:'.$url);};add_filter('wp_redirect',$redirect);
foreach([$actor,$target] as $id){$_POST=['user_id'=>(string)$id,'password'=>$password,'confirm'=>'1','_wpnonce'=>wp_create_nonce('amsec_sessions_revoke_'.$id)];$_REQUEST=$_POST;try{(new SessionAction())->handle();throw new LogicException('No redirect.');}catch(RuntimeException $e){if(!str_starts_with($e->getMessage(),'redirect:')){throw $e;}}}
remove_filter('wp_redirect',$redirect);remove_filter('wp_die_handler',$die);
if(!$manager->verify($keep)||$manager->verify($other)||$targetManager->verify($targetToken)){throw new RuntimeException('Session preservation/revocation failed.');}
$_GET=['user_id'=>(string)$actor];ob_start();(new SessionPage())->render();$html=ob_get_clean();if(str_contains($html,$keep)||str_contains($html,$other)||!str_contains($html,'cannot be undone')){throw new RuntimeException('Session page leaked tokens or omitted impact.');}
wp_set_current_user(1);$_COOKIE=[];wp_delete_user($actor);wp_delete_user($target);
echo 'Session action: valid cookie/HTTPS/nonce/password/role gates; other-session and selected-account revocation; current session preserved; tokens redacted.' . PHP_EOL;
