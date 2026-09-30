<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\{PasskeyHandle,Base64Url};
final class HandleTest extends TestCase {
 public function testOwnHandleIsFreshCanonicalStableAndNeverCreatedByRead():void {
 $db=new HandleDb();$h=new PasskeyHandle($db);self::assertNull($h->get(4,false));self::assertSame([],$db->queries);$value=$h->get(4,true);self::assertSame(32,strlen($value));self::assertSame($value,$h->get(4,true));self::assertCount(1,$db->queries);self::assertTrue($db->released);self::assertFalse($db->suppressed);self::assertStringContainsString('FROM wp_users',$db->queries[0]);self::assertStringContainsString('NOT EXISTS',$db->queries[0]);
 }
 public function testMalformedDuplicateBusyFullAndFailedHandleStateRefuses():void {
 foreach([['rows'=>[['meta_value'=>'bad']]],['rows'=>[['meta_value'=>Base64Url::encode(random_bytes(32))],['meta_value'=>Base64Url::encode(random_bytes(32))]]],['lock'=>'0'],['total'=>10000],['fail'=>true]] as $change){$db=new HandleDb();foreach($change as $k=>$v)$db->$k=$v;self::assertNull((new PasskeyHandle($db))->get(4,true));self::assertFalse($db->suppressed);}
 $db=new HandleDb();self::assertNull((new PasskeyHandle($db))->get(0,true));self::assertSame([],$db->queries);
 }
}
final class HandleDb {
 public string $usermeta='wp_usermeta';public string $users='wp_users';public string $last_error='';public bool $suppressed=false;public bool $released=false;public bool $fail=false;public string $lock='1';public int $total=0;public array $rows=[];public array $queries=[];public array $args=[];
 public function prepare(string $sql,mixed ...$args):string {$this->args[$sql]=$args;return $sql;}
 public function suppress_errors(bool $v):bool {$old=$this->suppressed;$this->suppressed=$v;return $old;}
 public function get_var(string $sql):mixed {if(str_contains($sql,'RELEASE_LOCK')){$this->released=true;return '1';}if(str_contains($sql,'GET_LOCK'))return $this->lock;return $this->total;}
 public function get_results(string $sql,string $format):array {return $this->rows;}
 public function query(string $sql):int|false {$this->queries[]=$sql;if($this->fail){$this->last_error='failed';return false;}$this->rows=[['meta_value'=>$this->args[$sql][1]]];return 1;}
}
