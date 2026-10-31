<?php
namespace AmazingPlugins\Security\Tests\Unit\Traffic;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Traffic\{TrafficPolicy,TrafficEvent,TrafficSettingsService};
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
final class TrafficPolicyEventTest extends TestCase {
 public function testPolicyRejectsCorruptExtraFieldsAndUnsupportedShapes():void {
 $p=new TrafficPolicy();self::assertFalse($p->read(null)['enabled']);$s=['version'=>1,'enabled'=>true,'revision'=>str_repeat('a',32)];self::assertSame($s,$p->read(json_encode($s)));
 foreach([false,'[]','corrupt',str_repeat('x',2049),json_encode($s+['ip'=>'secret']),json_encode(array_replace($s,['enabled'=>1])),json_encode(array_replace($s,['revision'=>'ABC']))] as $raw)self::assertNull($p->read($raw));
 }
 public function testRecordsDiscardSensitiveFieldsAndKeepOnlyFixedLabels():void {
 $e=TrafficEvent::capture(['REQUEST_METHOD'=>'post','REQUEST_URI'=>'/private/person?token=secret','REMOTE_ADDR'=>'192.0.2.2','HTTP_COOKIE'=>'secret'], '/wc/store/v1/cart?secret',200,'network-block',123);
 self::assertSame(['created_at'=>123,'method'=>'POST','category'=>'store-rest','status'=>200,'decision'=>'network-block'],$e->row());
 foreach(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'] as $m)self::assertSame($m,TrafficEvent::capture(['REQUEST_METHOD'=>$m],'',0,'unclassified',1)->row()['method']);
 $e=TrafficEvent::capture(['REQUEST_METHOD'=>'secret','SCRIPT_NAME'=>'/wp-login.php'],null,999,'invented-secret',1);self::assertSame(['created_at'=>1,'method'=>'OTHER','category'=>'login','status'=>0,'decision'=>'unclassified'],$e->row());
 }
 public function testCoarseCategoriesDoNotRetainRequestPaths():void {
 foreach([['/wp/v2/posts','core-rest'],['/wc/v3/orders/123','store-rest'],['/contact-form-7/v1/contact-forms/123/feedback','form-rest'],['/custom/person','other-rest']] as [$route,$category])self::assertSame($category,TrafficEvent::capture([], $route,403,'rest-rate-block',1)->row()['category']);
 foreach([['/xmlrpc.php','xmlrpc'],['/wordpress/wp-admin/admin-ajax.php','admin'],['/wordpress/index.php','frontend'],['/unknown.php','other']] as [$script,$category])self::assertSame($category,TrafficEvent::capture(['SCRIPT_NAME'=>$script],null,201,'unclassified',1)->row()['category']);
 self::assertSame('other',TrafficEvent::capture(['SCRIPT_NAME'=>str_repeat('x',3000)],null,200,'unclassified',1)->row()['category']);
 }
 public function testApprovalRechecksStateAndRecoveryNeverEnablesCorruption():void {
 $o=new MemoryOptions();$s=new TrafficSettingsService($o);$fp=$s->fingerprint();self::assertSame('saved',$s->apply($fp,true));self::assertTrue($s->status()['enabled']);self::assertSame('changed',$s->apply($fp,false));$fp=$s->fingerprint();$o->failWrites=true;self::assertSame('failed',$s->apply($fp,false));self::assertTrue($s->status()['enabled']);$o->failWrites=false;$o->values['amsec_traffic_policy']='broken';self::assertSame('invalid',$s->apply($s->fingerprint(),true));self::assertTrue($s->disable());self::assertFalse($s->status()['enabled']);
 }
}
