<?php
namespace AmazingPlugins\Security\Tests\Unit\Traffic;

use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Traffic\{TrafficCollector, TrafficRepository, TrafficEvent};
final class TrafficCollectorRepositoryTest extends TestCase {
	private function policy(): array {
		return array(
			'version'  => 1,
			'enabled'  => true,
			'revision' => str_repeat( 'b', 32 ),
		);}
	public function testCollectionIsOncePerSameEnabledRevisionAndSkipsRuntimeExemptions(): void {
		$p = $this->policy();
		$c = new TrafficCollector(
			$p,
			array(
				'REQUEST_METHOD' => 'GET',
				'SCRIPT_NAME'    => '/index.php',
			),
			false,
			false
		);
		$c->restRoute( '/wc/store/v1/cart' );
		$c->decision( 'network-block' );
		$c->decision( 'secret' );
		$e = $c->finish( $p, false, 403, 123 );
		self::assertSame( 'store-rest', $e->row()['category'] );
		self::assertSame( 'network-block', $e->row()['decision'] );
		self::assertNull( $c->finish( $p, false, 403, 123 ) );
		foreach ( array( array( null, false, false, $p, false ), array( $p, true, false, $p, false ), array( $p, false, true, $p, false ), array( $p, false, false, $p, true ), array( $p, false, false, array_replace( $p, array( 'enabled' => false ) ), false ), array( $p, false, false, array_replace( $p, array( 'revision' => str_repeat( 'c', 32 ) ) ), false ) ) as [$start, $cli, $cron, $end, $admin] ) {
			self::assertNull( ( new TrafficCollector( $start, array(), $cli, $cron ) )->finish( $end, $admin, 200, 123 ) );}
	}
	public function testRepositoryDropsOnBusyFullOrMinuteQuotaAndReleasesLock(): void {
		foreach ( array( array( 'lock' => '0' ), array( 'total' => 5000 ), array( 'minute' => 100 ), array( 'badCount' => true ), array( 'failInsert' => true ) ) as $change ) {
			$db = new TrafficDb();
			foreach ( $change as $k => $v ) {
				$db->$k = $v;
			}$r = new TrafficRepository( $db );
			self::assertFalse( $r->append( TrafficEvent::capture( array(), null, 200, 'unclassified', 1000 ), str_repeat( 'b', 32 ) ) );
			self::assertSame( '0' !== $db->lock, $db->released );
			self::assertFalse( $db->suppressed );}
		$db = new TrafficDb();
		$r  = new TrafficRepository( $db );
		self::assertTrue( $r->append( TrafficEvent::capture( array( 'REMOTE_ADDR' => 'secret' ), null, 200, 'unclassified', 1000 ), str_repeat( 'b', 32 ) ) );
		self::assertNotEmpty( $db->written );
		self::assertStringNotContainsString( 'secret', $db->written['sql'] );
		self::assertTrue( $db->released );
		self::assertFalse( $db->suppressed );
	}
	public function testRevisionAdmissionUsesFreshPolicyAndSkipsAdministratorIdentifiedEarlier(): void {
		$p          = $this->policy();
		$db         = new TrafficDb();
		$repo       = new TrafficRepository( $db );
		$db->policy = json_encode( array_replace( $p, array( 'enabled' => false ) ) );
		self::assertFalse( $repo->append( TrafficEvent::capture( array(), null, 200, 'unclassified', 1 ), str_repeat( 'b', 32 ) ) );
		self::assertFalse( $repo->currentPolicy()['enabled'] );
		$db->policy = json_encode( array_replace( $p, array( 'revision' => str_repeat( 'c', 32 ) ) ) );
		self::assertFalse( $repo->append( TrafficEvent::capture( array(), null, 200, 'unclassified', 1 ), str_repeat( 'b', 32 ) ) );
		$c = new TrafficCollector( $p, array(), false, false );
		$c->identifyAdministrator( true );
		$c->identifyAdministrator( false );
		self::assertNull( $c->finish( $p, false, 200, 1 ) );
	}
	public function testRepositoryThrowsOnReadOutageAndRejectsUnfixedFilter(): void {
		$db              = new TrafficDb();
		$db->readFailure = true;
		$r               = new TrafficRepository( $db );
		try {
			$r->page( 1, '' );
			self::fail( 'Read outage hidden.' );
		} catch ( \RuntimeException ) {
			self::assertFalse( $db->suppressed );
		} $this->expectException( \InvalidArgumentException::class );
		$r->page( 1, 'private-secret' );
	}
}
final class TrafficDb {
	public string $prefix     = 'wp_';
	public string $options    = 'wp_options';
	public string $last_error = '';
	public string $lock       = '1';
	public int $total         = 0;
	public int $minute        = 0;
	public bool $badCount     = false;
	public bool $released     = false;
	public bool $suppressed   = false;
	public bool $failInsert   = false;
	public bool $readFailure  = false;
	public array $written     = array();
	public string $policy     = '{"version":1,"enabled":true,"revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}';
	public function prepare( string $q, mixed ...$args ): string {
		foreach ( $args as $a ) {
			$q = preg_replace( '/%[sd]/', is_int( $a ) ? (string) $a : "'" . $a . "'", $q, 1 );
		}return $q; }
	public function suppress_errors( bool $v ): bool {
		$p                = $this->suppressed;
		$this->suppressed = $v;
		return $p;}
	public function get_var( string $q ): mixed {
		if ( str_contains( $q, 'RELEASE_LOCK' ) ) {
			$this->released = true;
			return '1';
		}if ( str_contains( $q, 'GET_LOCK' ) ) {
			return $this->lock;
		}if ( str_contains( $q, 'SELECT option_value' ) ) {
			return $this->policy;
		}if ( $this->badCount ) {
			return null;
		}return str_contains( $q, 'WHERE' ) ? $this->minute : $this->total; }
	public function insert( string $t, array $row, array $formats ): int|false {
		if ( $this->failInsert ) {
			$this->last_error = 'failed';
			return false;
		}$this->written = $row;
		return 1;}
	public function get_results( string $q, string $type ): ?array {
		if ( $this->readFailure ) {
			$this->last_error = 'read failed';
			return null;
		}return array();}
	public function query( string $q ): int|false {
		if ( str_starts_with( $q, 'INSERT' ) ) {
			if ( $this->failInsert ) {
				$this->last_error = 'failed';
				return false;
			}$this->written = array( 'sql' => $q );
			return 1;
		}return 0;}
}
