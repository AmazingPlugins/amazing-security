<?php
namespace AmazingPlugins\Security\Tests\Unit\Login;
use AmazingPlugins\Security\Login\RequiredTotpState;
use PHPUnit\Framework\TestCase;
final class RequiredTotpStateTest extends TestCase {
 public function test_grace_has_exact_expiry_and_generation_binding(): void {
  $generation=str_repeat('a',32);$record=['generation'=>$generation,'deadline'=>1000];
  self::assertSame('grace',RequiredTotpState::evaluate($record,$generation,999));
  self::assertSame('expired',RequiredTotpState::evaluate($record,$generation,1000));
  self::assertSame('new',RequiredTotpState::evaluate($record,str_repeat('b',32),1000));
 }
 public function test_corruption_cannot_repeatedly_grant_a_new_grace_period(): void {
  $generation=str_repeat('a',32);
  self::assertSame('new',RequiredTotpState::evaluate('', $generation,100));
  foreach([[],['generation'=>$generation],['generation'=>$generation,'deadline'=>'1000'],['generation'=>$generation,'deadline'=>0],['generation'=>'bad','deadline'=>1000]] as $bad){self::assertSame('unavailable',RequiredTotpState::evaluate($bad,$generation,100));}
 }
}
