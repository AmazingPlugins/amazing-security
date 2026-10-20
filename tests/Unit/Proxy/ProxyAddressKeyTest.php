<?php
namespace AmazingPlugins\Security\Tests\Unit\Proxy;
use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Login\AddressKey;
use AmazingPlugins\Security\Proxy\{ProxyNamespace,ProxyResolver};
final class ProxyAddressKeyTest extends TestCase {
 public function testInjectedResolutionUsesClientRatherThanProxyAndUnknownFailsOpen():void {
 $p=['version'=>1,'mode'=>'xff','cidrs'=>['10.0.0.0/8'],'revision'=>str_repeat('a',32)];$resolve=static fn(array $server)=>(new ProxyResolver())->resolve($p,$server,true);$key=new AddressKey('salt',$resolve);self::assertSame((new AddressKey('salt'))->fromServer(['REMOTE_ADDR'=>'192.0.2.4']),$key->fromServer(['REMOTE_ADDR'=>'10.0.0.1','HTTP_X_FORWARDED_FOR'=>'192.0.2.4']));self::assertNull($key->fromServer(['REMOTE_ADDR'=>'10.0.0.1']));self::assertNull((new AddressKey('salt',static function(){throw new \RuntimeException('failed');}))->fromServer(['REMOTE_ADDR'=>'192.0.2.4']));
 }
 public function testChangedProxyInterpretationGetsSeparateOpaqueNamespace():void {
 $s=['version'=>1,'mode'=>'xff','cidrs'=>['10.0.0.0/8'],'revision'=>str_repeat('a',32)];$a=ProxyNamespace::salt('salt',$s);$b=ProxyNamespace::salt('salt',array_replace($s,['revision'=>str_repeat('b',32)]));self::assertNotSame($a,$b);self::assertSame('salt',ProxyNamespace::salt('salt',array_replace($s,['mode'=>'off','revision'=>str_repeat('0',32)])));self::assertNotSame('salt',ProxyNamespace::salt('salt',array_replace($s,['mode'=>'off'])));$server=['REMOTE_ADDR'=>'192.0.2.4'];self::assertNotSame((new AddressKey($a))->fromServer($server),(new AddressKey($b))->fromServer($server));
 }

	public function test_prefix64_groups_ipv6_only(): void {
		$grouped = new \AmazingPlugins\Security\Login\AddressKey( 'salt', null, true );
		$plain   = new \AmazingPlugins\Security\Login\AddressKey( 'salt' );
		self::assertSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2:ffff::9' ) ) );
		self::assertNotSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:3::1' ) ) );
		self::assertNotSame( $plain->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $plain->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::2' ) ) );
		self::assertSame( $plain->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) ) );
	}

}
