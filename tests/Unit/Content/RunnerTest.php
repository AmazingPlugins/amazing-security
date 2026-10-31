<?php
namespace AmazingPlugins\Security\Tests\Unit\Content;
use AmazingPlugins\Security\Content\ContentCursor;
use AmazingPlugins\Security\Content\ContentRunner;
use AmazingPlugins\Security\Content\MarkupDetector;
use PHPUnit\Framework\TestCase;
final class RunnerTest extends TestCase {
 private function inventory(int $n=1):TestInventory{return new TestInventory($n);}
 public function test_fifty_item_steps_resume_without_losing_findings_or_scanning_new_ids():void{
  $i=$this->inventory(75);$c=new ContentCursor('test',75,0,1000,hash('sha256','site.test'));$r=new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0);$r->step($c,1000);self::assertSame(50,$c->processed);self::assertFalse($c->finished);$i->bodies['post'][76]='<a href="javascript:fixture">x</a>';$r->step($c,1001);self::assertSame(75,$c->processed);self::assertTrue($c->finished);self::assertFalse($c->partial);self::assertCount(75,$c->findings);self::assertStringNotContainsString('javascript',json_encode($c->toArray()));
 }
 public function test_changed_and_oversized_items_cannot_create_a_clean_result():void{
  $i=$this->inventory(2);$i->bodies['post'][1]=str_repeat('x',131073);$i->changed=true;$c=new ContentCursor('test',2,0,1000,hash('sha256','site.test'));(new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0))->step($c,1000);self::assertTrue($c->partial);self::assertTrue($c->finished);self::assertSame(2,$c->unknown);self::assertCount(0,$c->findings);
 }
 public function test_hard_item_and_byte_limits_stop_with_partial_coverage():void{
  $i=$this->inventory(2);$r=new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0);$c=new ContentCursor('test',2,0,1000,hash('sha256','site.test'));$c->processed=999;$r->step($c,1000);self::assertSame(1000,$c->processed);self::assertTrue($c->partial);self::assertTrue($c->finished);$c=new ContentCursor('test',2,0,1000,hash('sha256','site.test'));$c->bytes=16777215;$r->step($c,1000);self::assertTrue($c->finished);self::assertTrue($c->partial);self::assertSame(16777215,$c->bytes);
 }
 public function test_database_failure_and_finding_overflow_are_partial():void{
  $i=$this->inventory(1);$i->fail=true;$c=new ContentCursor('test',1,0,1000,hash('sha256','site.test'));(new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0))->step($c,1000);self::assertTrue($c->partial);self::assertTrue($c->finished);self::assertSame('database',$c->reason);
  $i=$this->inventory(251);$c=new ContentCursor('test',251,0,1000,hash('sha256','site.test'));$r=new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0);while(!$c->finished){$r->step($c,1000);}self::assertCount(250,$c->findings);self::assertSame(1,$c->omitted);self::assertTrue($c->partial);
 }
 public function test_oversized_items_cannot_bypass_total_item_budget():void{
  $i=$this->inventory(2);$i->bodies['post'][1]=str_repeat('x',131073);$i->bodies['post'][2]=str_repeat('x',131073);$c=new ContentCursor('test',2,0,1000,hash('sha256','site.test'));$c->processed=999;(new ContentRunner($i,new MarkupDetector('site.test'),static fn()=>0.0))->step($c,1000);self::assertSame(1000,$c->processed);self::assertTrue($c->finished);self::assertTrue($c->partial);
 }
 public function test_cursor_rejects_arbitrary_content_and_invalid_offsets():void{
  $c=new ContentCursor('test',2,0,1000,hash('sha256','site.test'));$data=$c->toArray();$data['findings']=[['kind'=>'post','id'=>1,'rule'=>'unknown','line'=>1]];self::assertNull(ContentCursor::fromArray($data));$data=$c->toArray();$data['after']=99;self::assertNull(ContentCursor::fromArray($data));
 }
}
