<?php
namespace AmazingPlugins\Security\Tests\Unit\Digest;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Activity\ActivityEvent;
use PHPUnit\Framework\TestCase;
final class ActivityTest extends TestCase {
 public function test_blocked_logins_share_failed_login_quota():void{
  $db=new class {public string $prefix='wp_';public string $last_error='';public array $queries=[];public function suppress_errors($v){return false;}public function prepare($q,...$args){$this->queries[]=$q;return $q;}public function get_var($q){return str_contains($q,'GET_LOCK')?'1':100;}public function insert(...$args){throw new \LogicException('quota should prevent write');}};
  self::assertFalse((new ActivityRepository($db))->append(new ActivityEvent('login_rate_blocked',0,0,'',1000)));self::assertStringContainsString("event IN (%s, %s)",implode(' ',$db->queries));
 }
 public function test_summary_is_bounded_numeric_and_storage_failure_is_explicit():void{
  $db=new class {public string $prefix='wp_';public string $last_error='';public function suppress_errors($v){return false;}public function prepare($q,...$args){return $q;}public function get_results($q,$mode){return [['event'=>'user_role_changed','total'=>'2'],['event'=>'login_rate_blocked','total'=>'3'],['event'=>'arbitrary','total'=>'999']];}};
  self::assertSame(['available'=>true,'changes'=>2,'blocked'=>3],(new ActivityRepository($db))->digestCounts(1000));$db->last_error='read failed';self::assertSame(['available'=>false],(new ActivityRepository($db))->digestCounts(1000));
 }
}
