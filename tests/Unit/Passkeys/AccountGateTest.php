<?php
namespace AmazingPlugins\Security\Tests\Unit\Passkeys;
require_once dirname(__DIR__).'/Login/TotpAuthenticationTest.php';
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Passkeys\PasskeyAccountGate;
final class AccountGateTest extends TestCase {
 private function state():array{return ['user'=>new \WP_User(7),'admin'=>true,'enrolled'=>true,'required'=>'enrolled','reset_required'=>false,'policy_revision'=>str_repeat('a',32),'account_revision'=>str_repeat('b',64),'fingerprint'=>str_repeat('c',64)];}
 public function testEnrolledAdministratorRequiresFactorAndRechecksStateBeforeGrant():void {
 $state=$this->state();$factors=0;$gate=new PasskeyAccountGate(static function()use(&$state){return $state;},static function($id,$factor,$now)use(&$factors){$factors++;return $id===7&&$factor==='valid'&&$now===1000;},static fn()=>false,static fn($user)=>$user);
 self::assertNull($gate->authorize(7,'wrong',1000));$permit=$gate->authorize(7,'valid',1000);self::assertSame(7,$permit['user']->ID);self::assertSame(2,$factors);self::assertSame(7,$gate->finalCheck($permit,1000)->ID);$state['fingerprint']=str_repeat('d',64);self::assertNull($gate->finalCheck($permit,1000));$state['reset_required']=true;self::assertNull($gate->authorize(7,'valid',1000));self::assertSame(2,$factors);
 }
 public function testPasskeyLoginAcceptsAnEnrolledAdministratorWithoutSpendingTheFactor(): void {
 $state = $this->state();
 $factors = 0;
 $gate = new PasskeyAccountGate(
  static function () use (&$state) { return $state; },
  static function () use (&$factors) { $factors++; return false; },
  static fn() => false,
  static fn($user) => $user
 );
 $permit = $gate->authorize(7, '', 1000, false);
 self::assertSame(7, $permit['user']->ID);
 self::assertSame(0, $factors);
 $state['reset_required'] = true;
 self::assertNull($gate->authorize(7, '', 1000, false));
 $state['reset_required'] = false;
 $state['required'] = 'expired';
 self::assertNull($gate->authorize(7, '', 1000, false));
 }
 public function testExpiredUnavailableDeletedReassignedOrChangedAccountsCannotAuthorize():void {
 foreach([['required'=>'expired'],['required'=>'unavailable'],['user'=>null],['user'=>new \WP_User(8)],['reset_required'=>true],['enrolled'=>false],['fingerprint'=>'bad']] as $change){$state=array_replace($this->state(),$change);$gate=new PasskeyAccountGate(static fn()=>$state,static fn()=>true,static fn()=>true,static fn($user)=>$user);self::assertNull($gate->authorize(7,'valid',1000));}
 $state=$this->state();foreach([static fn()=>new \WP_User(8),static fn()=>new \WP_Error('blocked','blocked'),static fn()=>null] as $filter){$gate=new PasskeyAccountGate(static fn()=>$state,static fn()=>true,static fn()=>true,$filter);self::assertNull($gate->authorize(7,'valid',1000));}
 $gate=new PasskeyAccountGate(static fn()=>$state,static function(){throw new \RuntimeException('unavailable');},static fn()=>false,static fn($user)=>$user);self::assertNull($gate->authorize(7,'valid',1000));
 }
 public function testNewGracePreservesPolicyAndCannotBypassConcurrentEnrollmentOrIncident():void {
 $state=array_replace($this->state(),['enrolled'=>false,'required'=>'new']);$factor=0;$gate=new PasskeyAccountGate(static function()use(&$state){return $state;},static function()use(&$factor){$factor++;return false;},static function()use(&$state){$state['required']='grace';$state['fingerprint']=str_repeat('e',64);return true;},static fn($user)=>$user);self::assertNotNull($gate->authorize(7,'',1000));self::assertSame(0,$factor);
 $state['required']='new';$gate=new PasskeyAccountGate(static function()use(&$state){return $state;},static fn()=>true,static function()use(&$state){$state['required']='grace';$state['policy_revision']=str_repeat('f',32);return true;},static fn($user)=>$user);self::assertNull($gate->authorize(7,'',1000));
 $state=$this->state();$gate=new PasskeyAccountGate(static function()use(&$state){return $state;},static function()use(&$state){$state['reset_required']=true;return true;},static fn()=>false,static fn($user)=>$user);self::assertNull($gate->authorize(7,'valid',1000));
 }
 public function testNonadminWithoutFactorUsesNativeAccountFilters():void {
 $state=array_replace($this->state(),['user'=>new \WP_User(7,false),'admin'=>false,'enrolled'=>false,'required'=>'off','policy_revision'=>'']);$filtered=false;$gate=new PasskeyAccountGate(static fn()=>$state,static function(){throw new \LogicException('Unneeded factor');},static fn()=>false,static function($user)use(&$filtered){$filtered=true;return $user;});self::assertNotNull($gate->authorize(7,'',1000));self::assertTrue($filtered);
 }
}
