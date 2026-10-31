<?php
namespace AmazingPlugins\Security\Tests\Unit\Proxy;

use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Proxy\{FreshSecurityOptions, SecurityApprovalLock};
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
final class ProxyApprovalGateTest extends TestCase {
	public function testPolicyReadsBypassCachedOptionsAndRestoreDatabaseErrorMode(): void {
		$db                                     = new ApprovalDb();
		$cached                                 = new MemoryOptions();
		$cached->values['amsec_proxy_policy']   = 'cached';
		$cached->values['unrelated']            = 'local';
		$cached->values['amsec_passkey_policy'] = 'cached-passkey';
		$o                                      = new FreshSecurityOptions( $db, $cached );
		self::assertSame( 'fresh', $o->get( 'amsec_proxy_policy' ) );
		self::assertSame( 'local', $o->get( 'unrelated' ) );
		self::assertSame( 'fresh', $o->get( 'amsec_passkey_policy' ) );
		self::assertFalse( $db->suppressed );
		$db->value = null;
		self::assertNull( $o->get( 'amsec_proxy_policy' ) );
		$db->broken = true;
		$this->expectException( \RuntimeException::class );
		$o->get( 'amsec_network_policy' );
	}
	public function testSharedApprovalLockRefusesBusyOrErrorAndAlwaysReleasesAfterCallback(): void {
		$db       = new ApprovalDb();
		$called   = 0;
		$lock     = new SecurityApprovalLock( $db );
		$db->lock = '0';
		self::assertSame(
			'busy',
			$lock->run(
				static function () use ( &$called ) {
					$called++;
					return 'saved';
				}
			)
		);
		self::assertSame( 0, $called );
		$db->lock = '1';
		self::assertSame(
			'saved',
			$lock->run(
				static function () use ( &$called ) {
					$called++;
					return 'saved';
				}
			)
		);
		self::assertTrue( $db->released );
		self::assertFalse( $db->suppressed );
		$db->released = false;
		self::assertSame(
			'failed',
			$lock->run(
				static function () {
					throw new \RuntimeException( 'outage' );
				}
			)
		);
		self::assertTrue( $db->released );
		self::assertFalse( $db->suppressed );
	}
}
final class ApprovalDb {
	public string $prefix     = 'wp_';
	public string $options    = 'wp_options';
	public string $last_error = '';
	public mixed $value       = 'fresh';
	public bool $broken       = false;
	public string $lock       = '1';
	public bool $released     = false;
	public bool $suppressed   = false;
	public function prepare( string $sql, mixed ...$args ): string {
		return $sql . ' ' . implode( ' ', $args );}
	public function get_var( string $q ): mixed {
		if ( str_contains( $q, 'RELEASE_LOCK' ) ) {
			$this->released = true;
			return '1';
		}if ( $this->broken ) {
			$this->last_error = 'failed';
			return null;
		}if ( str_contains( $q, 'GET_LOCK' ) ) {
			return $this->lock;
		}return $this->value;}
	public function suppress_errors( bool $v ): bool {
		$old              = $this->suppressed;
		$this->suppressed = $v;
		return $old;}
}
