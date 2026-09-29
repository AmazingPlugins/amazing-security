<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Fixes\FixProposal;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class FixRepositoryTest extends TestCase {
	public function test_proposal_has_exact_scope_and_expiry(): void {
		$proposal = new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-block', 'observe', 'block', 7, 1000, 1900 );
		self::assertSame( 'pending', $proposal->status );
		self::assertSame( 'observe', $proposal->beforeMode );
		self::assertSame( 'block', $proposal->afterMode );
		self::assertFalse( $proposal->isExpired( 1899 ) );
		self::assertTrue( $proposal->isExpired( 1900 ) );
		self::assertFalse( $proposal->canRollback( 1100 ) );
	}

	public function test_proposal_rejects_arbitrary_target_mode(): void {
		$this->expectException( InvalidArgumentException::class );
		new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-block', 'observe', 'delete_files', 7, 1000, 1900 );
	}
}
