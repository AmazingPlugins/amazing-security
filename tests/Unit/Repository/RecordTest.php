<?php
namespace AmazingPlugins\Security\Tests\Unit\Repository;
use AmazingPlugins\Security\Repository\DirectoryRecord;
use PHPUnit\Framework\TestCase;
final class RecordTest extends TestCase {
 private int $now;
 protected function setUp():void{$this->now=strtotime('2026-09-30 UTC');}
 private function parse($data,int $http=200):array{return (new DirectoryRecord())->parse($http,json_encode($data),'sample-plugin',$this->now);}
 public function test_explicit_closed_404_and_withheld_reason():void{$r=$this->parse(['error'=>'closed','slug'=>'sample-plugin','closed'=>true,'closed_date'=>'2021-11-12','reason'=>'security-issue'],404);self::assertSame('closed',$r['state']);self::assertSame('security-issue',$r['reason']);self::assertSame('2021-11-12',$r['closed_date']);$r=$this->parse(['error'=>'closed','slug'=>'sample-plugin','closed'=>true,'closed_date'=>false,'reason'=>false],404);self::assertSame('closed',$r['state']);self::assertSame('unknown',$r['reason']);self::assertSame('',$r['closed_date']);}
 public function test_missing_wrong_slug_incomplete_statuses_and_malicious_metadata_are_not_closed():void{
  foreach([['error'=>'Plugin not found.'],['error'=>'closed','closed'=>true,'slug'=>'other'],['error'=>'closed','slug'=>'sample-plugin'],['slug'=>'sample-plugin','closed'=>true],['slug'=>'sample-plugin','version'=>'1.0','closed'=>'yes']] as $data){self::assertSame('unknown',$this->parse($data,404)['state']);}self::assertSame('unknown',$this->parse(['slug'=>'sample-plugin','version'=>'1.0'],500)['state']);$r=$this->parse(['slug'=>'sample-plugin','error'=>'closed','closed'=>true,'reason'=>'<script>bad</script>','closed_date'=>"2026-09-30\0"],404);self::assertSame('unknown',$r['reason']);self::assertSame('',$r['closed_date']);self::assertStringNotContainsString('<script>',json_encode($r));
 }
 public function test_listing_update_age_never_claims_abandonment():void{$r=$this->parse(['slug'=>'sample-plugin','version'=>'1.2.3','last_updated'=>'2026-08-18 11:42pm GMT']);self::assertSame('listed',$r['state']);self::assertFalse($r['old_update']);$r=$this->parse(['slug'=>'sample-plugin','version'=>'1.0','last_updated'=>'2020-01-01 9:02am GMT']);self::assertTrue($r['old_update']);self::assertStringNotContainsString('abandon',json_encode($r));}
 public function test_future_or_invalid_update_is_unknown_without_removing_listing_observation():void{foreach(['2027-01-01 1:00am GMT','2026-02-30 1:00am GMT',"2026-09-30\0",'<script>date</script>'] as $date){$r=$this->parse(['slug'=>'sample-plugin','version'=>'1.0','last_updated'=>$date]);self::assertSame('listed',$r['state']);self::assertNull($r['updated_at']);self::assertFalse($r['old_update']);}}
 public function test_invalid_or_oversized_json_and_versions_are_unknown():void{$p=new DirectoryRecord();foreach(['bad',str_repeat('x',65537),'[]'] as $body){self::assertSame('unknown',$p->parse(200,$body,'sample-plugin',$this->now)['state']);}self::assertSame('unknown',$this->parse(['slug'=>'sample-plugin','version'=>str_repeat('1',65)])['state']);}
}
