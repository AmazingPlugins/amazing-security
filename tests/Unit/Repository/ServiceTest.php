<?php
namespace AmazingPlugins\Security\Tests\Unit\Repository;

use AmazingPlugins\Security\Repository\DirectoryService;
use AmazingPlugins\Security\Repository\DirectoryClient;
use AmazingPlugins\Security\Repository\DirectoryRecord;
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
use PHPUnit\Framework\TestCase;
final class ServiceTest extends TestCase {
	private function fixture(): array {
		$o = new MemoryOptions();
		$i = new class(){public array $item = array(
			'slug'        => 'sample-plugin',
			'version'     => '1.0',
			'fingerprint' => '',
			'supported'   => true,
		);
		public function __construct() {
			$this->item['fingerprint'] = str_repeat( 'f', 64 );
		}public function find( $key ) {
			return $this->item;
		}};
		$c = new class() implements DirectoryClient {public int $calls = 0;
			public mixed $during                                       = null;
			public array $reply;
			public function __construct() {
				$this->reply = ( new DirectoryRecord() )->parse(
					404,
					json_encode(
						array(
							'slug'   => 'sample-plugin',
							'error'  => 'closed',
							'closed' => true,
							'reason' => 'security-issue',
						)
					),
					'sample-plugin',
					1000
				);
			}public function fetch( string $slug, int $now ): array {
				++$this->calls;
				if ( is_callable( $this->during ) ) {
					( $this->during )();
				}return $this->reply;
			}};
		return array( $o, $i, $c, new DirectoryService( $o, $c, array( $i, 'find' ) ) );
	}
	public function test_outage_preserves_prior_closure_and_reopen_retains_history(): void {
		[$o, $i, $c, $s] = $this->fixture();
		$key             = str_repeat( 'a', 32 );
		$fp              = $i->item['fingerprint'];
		self::assertSame( 'saved', $s->lookup( $key, $fp, 1000 ) );
		self::assertSame( 'cached', $s->lookup( $key, $fp, 1001 ) );
		self::assertSame( 1, $c->calls );
		$c->reply = ( new DirectoryRecord() )->unknown();
		self::assertSame( 'saved', $s->lookup( $key, $fp, 1601 ) );
		$row = $s->status()['records'][ $key ];
		self::assertSame( 'unknown', $row['result']['state'] );
		self::assertSame( 'closed', $row['last_closed']['result']['state'] );
		$c->reply = ( new DirectoryRecord() )->parse(
			200,
			json_encode(
				array(
					'slug'    => 'sample-plugin',
					'version' => '1.1',
				)
			),
			'sample-plugin',
			2202
		);
		self::assertSame( 'saved', $s->lookup( $key, $fp, 2202 ) );
		$row = $s->status()['records'][ $key ];
		self::assertSame( 'listed', $row['result']['state'] );
		self::assertSame( 1000, $row['last_closed']['checked_at'] );}
	public function test_current_closure_without_matching_history_is_invalid(): void {
		[$o, $i, $c, $s] = $this->fixture();
		$key             = str_repeat( 'a', 32 );
		$fp              = $i->item['fingerprint'];
		$s->lookup( $key, $fp, 1000 );
		$state                                   = json_decode( $o->values['amsec_repository_state'], true );
		$state['records'][ $key ]['last_closed'] = null;
		$o->values['amsec_repository_state']     = json_encode( $state );
		self::assertSame( array( 'invalid' => true ), $s->status() );
		self::assertSame( 'invalid', $s->lookup( $key, $fp, 1601 ) );
		self::assertSame( 1, $c->calls );}
	public function test_clock_rewind_preserves_history_without_request(): void {
		[$o, $i, $c, $s] = $this->fixture();
		$key             = str_repeat( 'a', 32 );
		$fp              = $i->item['fingerprint'];
		$s->lookup( $key, $fp, 1000 );
		$before = $o->values['amsec_repository_state'];
		self::assertSame( 'failed', $s->lookup( $key, $fp, 999 ) );
		self::assertSame( $before, $o->values['amsec_repository_state'] );
		self::assertSame( 1, $c->calls );}
	public function test_changed_target_before_and_after_request_does_not_save(): void {
		[$o, $i, $c, $s] = $this->fixture();
		$key             = str_repeat( 'a', 32 );
		self::assertSame( 'changed', $s->lookup( $key, str_repeat( '0', 64 ), 1000 ) );
		self::assertSame( 0, $c->calls );
		$fp        = $i->item['fingerprint'];
		$c->during = static function () use ( $i ) {
			$i->item['fingerprint'] = str_repeat( 'e', 64 );
		};
		self::assertSame( 'changed', $s->lookup( $key, $fp, 1000 ) );
		self::assertArrayNotHasKey( 'amsec_repository_state', $o->values );}
	public function test_failed_save_cas_and_invalid_state_never_claim_saved_result(): void {
		[$o, $i, $c, $s]         = $this->fixture();
		$key                     = str_repeat( 'a', 32 );
		$fp                      = $i->item['fingerprint'];
		$o->failRepositoryWrites = true;
		self::assertSame( 'failed', $s->lookup( $key, $fp, 1000 ) );
		self::assertArrayNotHasKey( 'amsec_repository_state', $o->values );
		$o->failRepositoryWrites = false;
		$s->lookup( $key, $fp, 1000 );
		$c->during = static function () use ( $o ) {
			$o->values['amsec_repository_state'] = 'changed';
		};
		self::assertSame( 'failed', $s->lookup( $key, $fp, 1601 ) );
		self::assertSame( 'changed', $o->values['amsec_repository_state'] );
		self::assertSame( 'invalid', $s->lookup( $key, $fp, 2202 ) );}
	public function test_record_capacity_and_busy_worker_are_bounded(): void {
		[$o, $i, $c, $s] = $this->fixture();
		$fp              = $i->item['fingerprint'];for ( $n = 0;$n < 100;$n++ ) {
			self::assertSame( 'saved', $s->lookup( str_pad( dechex( $n ), 32, '0', STR_PAD_LEFT ), $fp, 1000 ) );
		}self::assertSame( 'full', $s->lookup( str_repeat( 'e', 32 ), $fp, 1000 ) );
		self::assertSame( 100, $c->calls );
		$o->values['amsec_repository_lock'] = json_encode( array( 'expires' => time() + 60 ) );
		self::assertSame( 'busy', $s->lookup( str_repeat( 'a', 32 ), $fp, 2000 ) );}
}
