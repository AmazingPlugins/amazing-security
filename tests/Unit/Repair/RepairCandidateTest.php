<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Repair;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Repair\RepairCandidate;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class RepairCandidateTest extends TestCase {
	public function test_accepts_only_a_completed_repository_plugin_mismatch_with_scanned_sha256(): void {
		$now = new DateTimeImmutable();
		$id = str_repeat( 'a', 32 );
		$finding = new CheckResult( 'integrity-file', 'warn', 'Different.', 'https://wordpress.org/', $now, 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'hello-dolly:1.7.2', 'path' => 'hello.php', 'reason' => 'ok', 'observed_sha256' => str_repeat( 'b', 64 ) ), $id );
		$run = new ScanRun( $now, $now, array( $finding ), false );
		$candidate = RepairCandidate::fromReport( $run, $id );
		self::assertNotNull( $candidate );
		self::assertSame( 'hello-dolly', $candidate->slug );
		self::assertNotNull( RepairCandidate::fromReport( new ScanRun( $now, $now, array( $finding ), true ), $id ) );
		self::assertNull( RepairCandidate::fromReport( $run, str_repeat( 'c', 32 ) ) );
	}

	public function test_rejects_unsafe_and_unsupported_evidence(): void {
		$now = new DateTimeImmutable();
		foreach ( array( '../escape.php', '/absolute.php', 'nested/../escape.php' ) as $path ) {
			$finding = new CheckResult( 'integrity-file', 'warn', 'Different.', 'https://wordpress.org/', $now, 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'hello-dolly:1.7.2', 'path' => $path, 'reason' => 'ok', 'observed_sha256' => str_repeat( 'b', 64 ) ), str_repeat( 'a', 32 ) );
			self::assertNull( RepairCandidate::fromReport( new ScanRun( $now, $now, array( $finding ), false ), str_repeat( 'a', 32 ) ) );
		}
	}
}
