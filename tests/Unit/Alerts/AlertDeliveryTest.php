<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Integrity\OptionGateway;
use PHPUnit\Framework\TestCase;

final class AlertDeliveryTest extends TestCase {
	public function test_accepted_alert_is_deduplicated_by_finding_id(): void {
		$options = $this->options();
		$sent = array();
		$delivery = new AlertDelivery( $options, static function ( string $to, string $subject, string $body ) use ( &$sent ): bool { $sent[] = array( $to, $subject, $body ); return true; }, 'owner@example.test', 'https://example.test/wp-admin/admin.php?page=amazing-security' );
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'none', $delivery->sendNew( array( 'finding-one' ), 1001 ) );
		self::assertCount( 1, $sent );
		self::assertStringContainsString( 'finding-one', $sent[0][2] );
		self::assertSame( 'accepted', $delivery->status()['last_attempt']['status'] );
	}

	public function test_mail_failure_can_retry_without_marking_as_sent(): void {
		$options = $this->options();
		$attempts = 0;
		$delivery = new AlertDelivery( $options, static function () use ( &$attempts ): bool { ++$attempts; return $attempts > 1; }, 'owner@example.test', 'https://example.test/report' );
		self::assertSame( 'failed', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( 'accepted', $delivery->sendNew( array( 'finding-one' ), 1001 ) );
		self::assertSame( 2, $attempts );
	}

	public function test_opt_out_sends_nothing(): void {
		$options = $this->options();
		$options->values['amsec_alerts_enabled'] = '0';
		$delivery = new AlertDelivery( $options, static function (): never { throw new \RuntimeException( 'Should not mail.' ); }, 'owner@example.test', 'https://example.test/report' );
		self::assertSame( 'off', $delivery->sendNew( array( 'finding-one' ), 1000 ) );
		self::assertSame( array(), $delivery->status() );
	}

	private function options(): OptionGateway {
		return new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( isset( $this->values[ $key ] ) ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } $this->values[ $key ] = $replacement; return true; }
			public function deleteIfSame( string $key, string $expected ): bool { if ( ( $this->values[ $key ] ?? null ) !== $expected ) { return false; } unset( $this->values[ $key ] ); return true; }
		};
	}
}
