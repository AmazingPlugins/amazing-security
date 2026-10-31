<?php
namespace AmazingPlugins\Security\Tests\Unit\Content;

use AmazingPlugins\Security\Content\ContentService;
use AmazingPlugins\Security\Content\MarkupDetector;
use AmazingPlugins\Security\Tests\Unit\Digest\MemoryOptions;
use PHPUnit\Framework\TestCase;
final class ServiceTest extends TestCase {
	private function service( $o, $i, $host = 'site.test' ): ContentService {
		return new ContentService( $o, $i, new MarkupDetector( $host ), hash( 'sha256', $host ), static fn()=>0.0 );}
	public function test_old_resume_id_cannot_advance_replacement_scan(): void {
		$o = new MemoryOptions();
		$i = new TestInventory( 1 );
		$s = $this->service( $o, $i );
		$s->start( 1000 );
		$old = $s->status()['active']['scan_id'];
		$s->step( 1001 );
		$s->start( 1002 );
		$before = $o->values['amsec_content_state'];
		self::assertSame( 'changed', $s->step( 1003, $old ) );
		self::assertSame( $before, $o->values['amsec_content_state'] );
		self::assertSame( 0, $s->status()['active']['processed'] );
	}
	public function test_start_resume_and_atomic_state(): void {
		$o = new MemoryOptions();
		$i = new TestInventory( 75 );
		$s = $this->service( $o, $i );
		self::assertSame( 'started', $s->start( 1000 ) );
		self::assertSame( 'busy', $s->start( 1001 ) );
		self::assertSame( 'progress', $s->step( 1001 ) );
		self::assertSame( 'finished', $s->step( 1002 ) );
		self::assertCount( 75, $s->status()['complete']['findings'] );
		self::assertStringNotContainsString( 'javascript', $o->values['amsec_content_state'] );
	}
	public function test_expiry_context_change_and_partial_work_preserve_previous_report(): void {
		$o = new MemoryOptions();
		$i = new TestInventory( 1 );
		$s = $this->service( $o, $i );
		$s->start( 1000 );
		$s->step( 1001 );
		$s->start( 1002 );
		self::assertSame( 'partial', $s->step( 1002 + 86401 ) );
		self::assertCount( 1, $s->status()['complete']['findings'] );
		self::assertSame( 'expired', $s->status()['previous']['reason'] );
		self::assertSame( 'started', $s->start( 90000 ) );
		self::assertSame( 'partial', $this->service( $o, $i, 'changed.test' )->step( 90001 ) );
		self::assertSame( 'context', $s->status()['active']['reason'] );
	}
	public function test_queue_write_failure_and_concurrent_state_cannot_claim_saved_progress(): void {
		$o = new MemoryOptions();
		$i = new TestInventory( 1 );
		$s = $this->service( $o, $i );
		$s->start( 1000 );
		$old                  = $o->values['amsec_content_state'];
		$o->failContentWrites = true;
		self::assertSame( 'failed', $s->step( 1001 ) );
		self::assertSame( $old, $o->values['amsec_content_state'] );
		$o->failContentWrites = false;
		$i->duringRead        = static function () use ( $o ) {
			$other                            = json_decode( $o->values['amsec_content_state'], true );
			$other['active']['scan_id']       = 'concurrent';
			$o->values['amsec_content_state'] = json_encode( $other );
		};
		self::assertSame( 'failed', $s->step( 1001 ) );
		self::assertSame( 'concurrent', $s->status()['active']['scan_id'] );
	}
	public function test_failed_storage_does_not_claim_progress_and_busy_worker_is_excluded(): void {
		$o = new MemoryOptions();
		$s = $this->service( $o, new TestInventory() );
		$s->start( 1000 );
		$o->values['amsec_content_lock'] = json_encode( array( 'expires' => time() + 60 ) );
		self::assertSame( 'busy', $s->step( 1001 ) );
		unset( $o->values['amsec_content_lock'] );
		$o->failWrites = true;
		self::assertSame( 'busy', $s->step( 1001 ) );
		$o->failWrites                    = false;
		$o->values['amsec_content_state'] = 'invalid';
		self::assertSame( 'invalid', $s->step( 1001 ) );
	}
}
