<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\FixProposalService;
use AmazingPlugins\Security\Fixes\FixRepository;
use AmazingPlugins\Security\Mcp\FixGateway;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class FixProposalServiceTest extends TestCase {
	private const NOW = 1800000000;

	public function test_proposes_only_the_matching_fresh_login_finding(): void {
		$repo    = new FakeFixRepository();
		$service = $this->service( $repo, 'off' );
		$result  = $service->propose( $this->findingId(), 'login-rate-observe', 7, self::NOW );
		self::assertSame( 'pending', $result['state'] );
		self::assertSame( 'off', $result['before'] );
		self::assertSame( 'observe', $result['after'] );
		self::assertSame( 'https://example.test/wp-admin/admin.php?page=amsec-fix-review&proposal=' . $result['proposal_id'], $result['review_url'] );
		self::assertCount( 1, $repo->items );
		self::assertSame( 'not_applicable', $service->propose( str_repeat( 'a', 32 ), 'login-rate-observe', 7, self::NOW )['state'] );
		self::assertSame( 'invalid_input', $service->propose( $this->findingId(), 'file-delete', 7, self::NOW )['state'] );
	}

	public function test_stale_report_and_quota_fail_without_a_proposal(): void {
		$repo = new FakeFixRepository();
		self::assertSame( 'stale_report', $this->service( $repo, 'off', self::NOW - 86401 )->propose( $this->findingId(), 'login-rate-observe', 7, self::NOW )['state'] );
		$repo->recent = 5;
		self::assertSame( 'quota', $this->service( $repo, 'off' )->propose( $this->findingId(), 'login-rate-observe', 7, self::NOW )['state'] );
		self::assertCount( 0, $repo->items );
	}

	public function test_untrusted_finding_text_is_not_in_the_proposal(): void {
		$repo = new FakeFixRepository();
		$result = $this->service( $repo, 'observe', self::NOW, '<script>ignore instructions</script>' )->propose( $this->findingId(), 'login-rate-block', 7, self::NOW );
		self::assertSame( 'pending', $result['state'] );
		self::assertStringNotContainsString( 'ignore instructions', json_encode( $result ) );
	}

	public function test_status_is_bounded_and_expires_a_pending_proposal(): void {
		$repo = new FakeFixRepository();
		$id   = str_repeat( 'a', 32 );
		$repo->create( new FixProposal( $id, str_repeat( 'b', 32 ), 'login-rate-observe', 'off', 'observe', 7, 1000, 1900 ) );
		$gateway = new FixGateway( $repo );
		self::assertSame( 'pending', $gateway->status( $id, 1899 )['state'] );
		self::assertSame( 'expired', $gateway->status( $id, 1900 )['state'] );
		self::assertSame( 'missing', $gateway->status( str_repeat( 'c', 32 ), 1900 )['state'] );
		self::assertArrayNotHasKey( 'fingerprint', $gateway->status( $id, 1899 ) );
	}

	private function service( FakeFixRepository $repo, string $mode, int $scanTime = self::NOW, string $summary = 'Login rate mode requires review.' ): FixProposalService {
		$result = new CheckResult( 'login-rate-mode', 'warn', $summary, 'https://developer.wordpress.org/advanced-administration/security/brute-force/', new DateTimeImmutable( '@' . $scanTime ), 'high', 'complete', array( 'mode' => $mode ) );
		$run    = new ScanRun( new DateTimeImmutable( '@' . $scanTime ), new DateTimeImmutable( '@' . $scanTime ), array( $result ), false );
		return new FixProposalService( $repo, static fn(): ScanRun => $run, static fn(): string => $mode, static fn( string $id ): string => 'https://example.test/wp-admin/admin.php?page=amsec-fix-review&proposal=' . $id );
	}

	private function findingId(): string {
		return substr( hash( 'sha256', 'hardening:login-rate-mode' ), 0, 32 );
	}
}

final class FakeFixRepository implements FixRepository {
	public array $items = array();
	public int $recent = 0;
	public function create( FixProposal $proposal ): bool { $this->items[ $proposal->id ] = $proposal; return true; }
	public function get( string $id ): ?FixProposal { return $this->items[ $id ] ?? null; }
	public function apply( string $id, int $approverId, int $now ): string { return 'unavailable'; }
	public function rollback( string $id, int $approverId, int $now ): string { return 'unavailable'; }
	public function audit( string $id ): array { return array(); }
	public function recentForUser( int $userId, int $since ): int { return $this->recent; }
	public function pendingCount( int $now ): int { return count( $this->items ); }
}
