<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Passkeys\{PasskeySettingsService,PasskeyContext};
final class SettingsServiceTest extends TestCase {
 public function testOnlyExactPolicyAndSupportedContextEnableAndRevisionChangesOnEverySave():void {
 $o=new PasskeyOptionsFake();$s=new PasskeySettingsService($o);self::assertFalse($s->status()['enabled']);$f=$s->fingerprint();self::assertSame('changed',$s->apply('wrong',true,PasskeyContext::fromSiteUrl('https://example.com')));self::assertSame('unavailable',$s->apply($f,true,null));self::assertSame('saved',$s->apply($f,true,PasskeyContext::fromSiteUrl('https://example.com')));$first=$s->status()['revision'];self::assertTrue($s->status()['enabled']);self::assertSame('changed',$s->apply($f,false,null));self::assertSame('saved',$s->apply($s->fingerprint(),false,null));self::assertNotSame($first,$s->status()['revision']);self::assertFalse($s->status()['enabled']);
 }
 public function testCorruptPolicyRefusesNormalSaveButExplicitRecoveryDisablesWithFreshRevision():void {
 $o=new PasskeyOptionsFake();$o->raw='bad';$s=new PasskeySettingsService($o);self::assertTrue($s->status()['invalid']);self::assertSame('invalid',$s->apply($s->fingerprint(),true,PasskeyContext::fromSiteUrl('https://example.com')));self::assertTrue($s->disable());self::assertFalse($s->status()['enabled']);$rev=$s->status()['revision'];self::assertTrue($s->disable());self::assertNotSame($rev,$s->status()['revision']);$o->fail=true;self::assertSame('failed',$s->apply($s->fingerprint(),false,null));self::assertFalse($s->disable());
 }
}
final class PasskeyOptionsFake implements OptionGateway {
 public mixed $raw=null;public bool $fail=false;
 public function get(string $key):mixed{return $this->raw;}
 public function add(string $key,string $value):bool{if($this->fail||$this->raw!==null)return false;$this->raw=$value;return true;}
 public function set(string $key,string $value):bool{if($this->fail)return false;$this->raw=$value;return true;}
 public function delete(string $key):void{$this->raw=null;}
 public function replaceIfSame(string $key,string $expected,string $replacement):bool{if($this->fail||$this->raw!==$expected)return false;$this->raw=$replacement;return true;}
 public function deleteIfSame(string $key,string $expected):bool{if($this->raw!==$expected)return false;$this->raw=null;return true;}
}
