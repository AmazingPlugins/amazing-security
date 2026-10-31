<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Integrity\OptionGateway;
use PHPUnit\Framework\TestCase;

final class AlertDeliveryTest extends TestCase {
	public function test_partial_history_does_not_drop_sent_or_pending_ids(): void {
		$options = $this->options();
		$ids     = array_map( static fn( int $n ): string => 'finding-' . $n, range( 1, 1000 ) );
		$options->set(
			'amsec_alert_state',
			json_encode(
				array(
					'active'  => array( 'vulnerabilities' => $ids ),
					'pending' => array( 'finding-1000' ),
				)
			)
		);
		$messages = array();
		$delivery = new AlertDelivery(
			$options,
			static function ( $to, $subject, $body ) use ( &$messages ): bool {
				$messages[] = $body;
				return true;
			},
			'owner@example.test',
			'https://example.test/report'
		);
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-1001' ), 1000, 'vulnerabilities', false ) );
		self::assertStringContainsString( "finding-1000\n", $messages[0] );
		self::assertSame( 'none', $delivery->sendNew( array( 'finding-1000' ), 1001, 'vulnerabilities', false ) );
		self::assertCount( 1001, $delivery->status()['active']['vulnerabilities'] );
	}

	public function test_accepted_alert_is_deduplicated_by_finding_id(): void {
		$options  = $this->options();
		$sent     = array();
		$delivery = new AlertDelivery(
			$options,
			static function ( string $to, string $subject, string $body ) use ( &$sent ): bool {
				$sent[] = array( $to, $subject, $body );
				return true;
			},
			'owner@example.test',
			'https://example.test/wp-admin/admin.php?page=amsec-security-scanner'
		);
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'none', $delivery->sendNew( array( 'finding-one' ), 1001 ) );
		self::assertCount( 1, $sent );
		self::assertStringContainsString( 'finding-one', $sent[0][2] );
		self::assertSame( 'accepted', $delivery->status()['last_attempt']['status'] );
	}

	public function test_mail_failure_can_retry_without_marking_as_sent(): void {
		$options  = $this->options();
		$attempts = 0;
		$delivery = new AlertDelivery(
			$options,
			static function () use ( &$attempts ): bool {
				++$attempts;
				return $attempts > 1;
			},
			'owner@example.test',
			'https://example.test/report'
		);
		self::assertSame( 'failed', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1001 ) );
		self::assertSame( 2, $attempts );
	}

	public function test_missing_setting_sends_nothing(): void {
		$options = $this->options();
		unset( $options->values['amsec_alerts_enabled'] );
		$delivery = new AlertDelivery(
			$options,
			static function (): never {
				throw new \RuntimeException( 'Should not mail.' );
			},
			'owner@example.test',
			'https://example.test/report'
		);
		self::assertSame( 'off', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'off', $delivery->retry( 1001 ) );
	}

	public function test_opt_out_sends_nothing(): void {
		$options                                 = $this->options();
		$options->values['amsec_alerts_enabled'] = '0';
		$delivery                                = new AlertDelivery(
			$options,
			static function (): never {
				throw new \RuntimeException( 'Should not mail.' );
			},
			'owner@example.test',
			'https://example.test/report'
		);
		self::assertSame( 'off', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( array(), $delivery->status() );
	}

	public function test_resolved_finding_can_alert_again_when_it_returns(): void {
		$sent     = array();
		$delivery = new AlertDelivery(
			$this->options(),
			static function ( string $to, string $subject, string $body ) use ( &$sent ): bool {
				$sent[] = $body;
				return true;
			},
			'owner@example.test',
			'https://example.test/report'
		);
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'none', $delivery->sendNew( array(), 1001 ) );
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1002 ) );
		self::assertCount( 2, $sent );
	}

	public function test_overflow_is_kept_for_a_later_batch(): void {
		$sent     = array();
		$delivery = new AlertDelivery(
			$this->options(),
			static function ( string $to, string $subject, string $body ) use ( &$sent ): bool {
				$sent[] = $body;
				return true;
			},
			'owner@example.test',
			'https://example.test/report'
		);
		$ids      = array_map( static fn( int $n ): string => 'finding-' . $n, range( 1, 51 ) );
		self::assertSame( 'accepted', $delivery->sendNew( $ids, 1000 ) );
		self::assertCount( 1, $delivery->status()['pending'] );
		self::assertSame( 'accepted', $delivery->retry( 1001 ) );
		self::assertSame( array(), $delivery->status()['pending'] );
		self::assertCount( 2, $sent );
	}

	public function test_invalid_email_records_failure_and_preserves_pending(): void {
		$delivery = new AlertDelivery( $this->options(), static fn(): bool => true, 'bad-email', 'https://example.test/report' );
		self::assertSame( 'failed', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'failed', $delivery->status()['last_attempt']['status'] );
		self::assertSame( array( 'finding-one' ), $delivery->status()['pending'] );
	}

	private function options(): OptionGateway {
		$options                                 = new class() implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed {
				return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool {
				if ( isset( $this->values[ $key ] ) ) {
					return false;
				} $this->values[ $key ] = $value;
				return true; }
			public function set( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
				return true; }
			public function delete( string $key ): void {
				unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} $this->values[ $key ] = $replacement;
				return true; }
			public function deleteIfSame( string $key, string $expected ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} unset( $this->values[ $key ] );
				return true; }
		};
		$options->values['amsec_alerts_enabled'] = '1';
		return $options;
	}
}
