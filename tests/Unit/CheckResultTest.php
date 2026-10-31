<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class CheckResultTest extends TestCase {
	public function test_rejects_a_state_outside_the_five_supported_values(): void {
		$this->expectException( InvalidArgumentException::class );
		new CheckResult( 'file-editing', 'safe', 'File editing is off', 'https://developer.wordpress.org/', new DateTimeImmutable( '2026-09-28T00:00:00Z' ), 'high', 'complete', array() );
	}

	public function test_serializes_a_finding_with_source_time_and_coverage(): void {
		$result = new CheckResult( 'file-editing', State::WARN, 'File editing is enabled', 'https://developer.wordpress.org/advanced-administration/security/hardening/', new DateTimeImmutable( '2026-09-28T00:00:00+00:00' ), 'high', 'complete', array( 'enabled' => true ) );

		self::assertSame(
			array(
				'check_id'   => 'file-editing',
				'state'      => 'warn',
				'summary'    => 'File editing is enabled',
				'source_url' => 'https://developer.wordpress.org/advanced-administration/security/hardening/',
				'tested_at'  => '2026-09-28T00:00:00+00:00',
				'confidence' => 'high',
				'coverage'   => 'complete',
				'evidence'   => array( 'enabled' => true ),
			),
			$result->toArray()
		);
	}

	public function test_file_finding_id_survives_serialization_without_absolute_path(): void {
		$result = new CheckResult(
			'integrity-file',
			State::WARN,
			'Changed release file',
			'https://api.wordpress.org/',
			new DateTimeImmutable( '2026-09-28T00:00:00Z' ),
			'high',
			'complete',
			array(
				'package' => 'core',
				'path'    => 'wp-includes/version.php',
			),
			'safe-id'
		);
		self::assertSame( 'safe-id', CheckResult::fromArray( $result->toArray() )->findingId );
		self::assertStringNotContainsString( '/var/www/', json_encode( $result->toArray() ) );
	}
}
