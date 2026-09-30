<?php
namespace AmazingPlugins\Security\Tests\Unit\Proxy;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Proxy\ProxySettingsService;
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
final class ProxySettingsServiceTest extends TestCase {
 private function server():array{return ['REMOTE_ADDR'=>'10.0.0.1','HTTP_X_FORWARDED_FOR'=>'192.0.2.4'];}
 public function testHostPrerequisiteAndUnresolvedOperatorRefuseWithoutWrites():void {
 $o=new MemoryOptions();$s=new ProxySettingsService($o);$fp=$s->fingerprint();self::assertSame('host-unverified',$s->apply($fp,'xff',['10.0.0.0/8'],$this->server(),false));self::assertSame('unknown-operator',$s->apply($fp,'xff',['10.0.0.0/8'],['REMOTE_ADDR'=>'10.0.0.1'],true));self::assertNull($o->get('amsec_proxy_policy'));self::assertSame('unsupported',$s->apply($fp,'xff',['0.0.0.0/0'],$this->server(),true));
 }
 public function testCanonicalPolicyWritesExactStateAndChangedCorruptOrFailedStateRefuse():void {
 $o=new MemoryOptions();$s=new ProxySettingsService($o);$fp=$s->fingerprint();self::assertSame('saved',$s->apply($fp,'xff',['10.0.0.2/8'],$this->server(),true));self::assertSame(['10.0.0.0/8'],$s->status()['cidrs']);self::assertSame('changed',$s->apply($fp,'off',[],$this->server(),true));$fp=$s->fingerprint();$o->failWrites=true;self::assertSame('failed',$s->apply($fp,'off',[],$this->server(),true));$o->failWrites=false;$o->values['amsec_proxy_policy']='broken';self::assertSame('invalid',$s->apply($s->fingerprint(),'xff',['10.0.0.0/8'],$this->server(),true));self::assertTrue($s->disable());self::assertSame('off',$s->status()['mode']);
 }
 public function testResolvedOperatorCannotBeCoveredByExistingNetworkBlock():void {
 $o=new MemoryOptions();$o->values['amsec_network_policy']=json_encode(['version'=>1,'mode'=>'block','cidrs'=>['192.0.2.0/24'],'methods'=>['*'],'revision'=>str_repeat('c',32)]);$s=new ProxySettingsService($o);self::assertSame('self-lockout',$s->apply($s->fingerprint(),'xff',['10.0.0.0/8'],$this->server(),true));self::assertNull($o->get('amsec_proxy_policy'));$o->values['amsec_network_policy']='broken';self::assertSame('network-invalid',$s->apply($s->fingerprint(),'xff',['10.0.0.0/8'],$this->server(),true));
 }
}
