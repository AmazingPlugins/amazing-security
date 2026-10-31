<?php
namespace AmazingPlugins\Security\Tests\Unit\Digest;

use AmazingPlugins\Security\Digest\DigestDelivery;
use PHPUnit\Framework\TestCase;
final class DeliveryTest extends TestCase {
	private function options(): MemoryOptions {
		$o                                 = new MemoryOptions();
		$o->values['amsec_digest_enabled'] = '1';
		return $o;}
	private function delivery( $o, $send ): DigestDelivery {
		return new DigestDelivery( $o, $send, 'owner@example.test', 'https://example.test/wp-admin/admin.php?page=amsec-security-scanner' );}
	public function test_default_off_and_first_interval_do_not_send(): void {
		$o = new MemoryOptions();
		$d = $this->delivery(
			$o,
			static function () {
				throw new \LogicException( 'must not mail' );
			}
		);
		self::assertSame( 'off', $d->tick( array(), array(), 1000 ) );
		$o->values['amsec_digest_enabled'] = '1';
		self::assertSame( 'waiting', $d->tick( array(), array(), 1000 ) );
		self::assertSame( 'waiting', $d->tick( array(), array(), 605799 ) );
	}
	public function test_persists_inflight_before_send_and_deduplicates_interval(): void {
		$o    = $this->options();
		$sent = array();
		$d    = $this->delivery(
			$o,
			static function ( $to, $subject, $body ) use ( $o, &$sent ) {
				$state = json_decode( $o->values['amsec_digest_state'], true );
				self::assertSame( 'sending', $state['pending']['status'] );
				$sent[] = $body;
				return true;
			}
		);
		$d->tick( array(), array(), 1000 );
		self::assertSame( 'accepted', $d->tick( array(), array(), 605800 ) );
		self::assertSame( 'waiting', $d->tick( array(), array(), 605801 ) );
		self::assertCount( 1, $sent );
		self::assertNotNull( $d->status()['accepted'] );
	}
	public function test_failures_retry_with_backoff_and_stop_after_three(): void {
		$o        = $this->options();
		$attempts = 0;
		$d        = $this->delivery(
			$o,
			static function () use ( &$attempts ) {
				++$attempts;
				return false;
			}
		);
		$d->tick( array(), array(), 1000 );
		self::assertSame( 'failed', $d->tick( array(), array(), 605800 ) );
		self::assertSame( 'waiting', $d->tick( array(), array(), 605801 ) );
		self::assertSame( 'failed', $d->tick( array(), array(), 609400 ) );
		self::assertSame( 'failed', $d->tick( array(), array(), 613000 ) );
		self::assertSame( 'exhausted', $d->tick( array(), array(), 616600 ) );
		self::assertSame( 3, $attempts );
		self::assertNull( $d->status()['accepted'] );
	}
	public function test_failure_to_persist_prevents_mail(): void {
		$o = $this->options();
		$d = $this->delivery(
			$o,
			static function () {
				throw new \LogicException( 'must not mail' );
			}
		);
		$d->tick( array(), array(), 1000 );
		$o->failWrites = true;
		self::assertSame( 'busy', $d->tick( array(), array(), 605800 ) );
	}
	public function test_uncertain_outcome_is_not_resent(): void {
		$o     = $this->options();
		$count = 0;
		$d     = $this->delivery(
			$o,
			static function () use ( $o, &$count ) {
				++$count;
				$o->failWrites = true;
				return true;
			}
		);
		$d->tick( array(), array(), 1000 );
		self::assertSame( 'uncertain', $d->tick( array(), array(), 605800 ) );
		$o->failWrites = false;
		unset( $o->values['amsec_digest_lock'] );
		self::assertSame( 'uncertain', $d->tick( array(), array(), 609400 ) );
		self::assertSame( 1, $count );
	}
	public function test_queue_write_failure_prevents_mail_and_throwing_send_is_uncertain(): void {
		$o = $this->options();
		$d = $this->delivery(
			$o,
			static function () {
				throw new \RuntimeException( 'transport uncertain' );
			}
		);
		$d->tick( array(), array(), 1000 );
		$o->failStateWrites = true;
		self::assertSame( 'failed', $d->tick( array(), array(), 605800 ) );
		$o->failStateWrites = false;
		self::assertSame( 'uncertain', $d->tick( array(), array(), 605800 ) );
		self::assertSame( 'uncertain', $d->tick( array(), array(), 609400 ) );
	}
	public function test_busy_worker_cannot_send_and_optout_cancels_retry(): void {
		$o = $this->options();
		$d = $this->delivery( $o, static fn()=>false );
		$d->tick( array(), array(), 1000 );
		$o->values['amsec_digest_lock'] = json_encode( array( 'expires' => time() + 60 ) );
		self::assertSame( 'busy', $d->tick( array(), array(), 605800 ) );
		unset( $o->values['amsec_digest_lock'] );
		self::assertSame( 'failed', $d->tick( array(), array(), 605800 ) );
		$o->values['amsec_digest_enabled'] = '0';
		self::assertSame( 'off', $d->tick( array(), array(), 609400 ) );
	}
	public function test_new_week_supersedes_failed_queue_and_invalid_recipient_does_not_mail(): void {
		$o = $this->options();
		$d = new DigestDelivery(
			$o,
			static function () {
				throw new \LogicException( 'must not mail' );
			},
			'bad-email',
			'https://example.test/report'
		);
		$d->tick( array(), array(), 1000 );
		self::assertSame( 'failed', $d->tick( array(), array(), 605800 ) );
		self::assertSame( 'failed', $d->tick( array(), array(), 1210600 ) );
		self::assertSame( 1, $d->status()['pending']['attempts'] );
	}
}
