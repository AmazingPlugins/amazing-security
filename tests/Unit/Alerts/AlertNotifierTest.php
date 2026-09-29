<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertNotifier;
use AmazingPlugins\Security\Alerts\AlertPolicy;
use AmazingPlugins\Security\FileScan\FileScanReport;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AlertNotifierTest extends TestCase {
	public function test_partial_reports_do_not_send_or_clear_alert_history(): void {
		$options = new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { $this->values[ $key ] = $replacement; return true; }
			public function deleteIfSame( string $key, string $expected ): bool { unset( $this->values[ $key ] ); return true; }
		};
		$notifier = new AlertNotifier( new AlertPolicy(), new AlertDelivery( $options, static function (): never { throw new \RuntimeException( 'Unexpected email.' ); }, 'owner@example.test', 'https://example.test/report' ) );
		$now = new DateTimeImmutable( '@1000' );
		self::assertSame( 'none', $notifier->integrity( new ScanRun( $now, $now, array(), true ), 1000 ) );
		self::assertSame( 'none', $notifier->files( new FileScanReport( 'scan-1', 'inconclusive', $now, true, 0, 0, 0, 0, 0, 0, 0, 0, array() ), 1000 ) );
		self::assertSame( array(), $options->values );
	}
}
