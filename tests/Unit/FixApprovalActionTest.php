<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Admin\FixReviewPage;
use AmazingPlugins\Security\Fixes\FixProposal;
use PHPUnit\Framework\TestCase;

final class FixApprovalActionTest extends TestCase {
	public function test_review_shows_exact_setting_and_only_one_explicit_action(): void {
		$proposal = new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-observe', 'off', 'observe', 7, 1000, 1900 );
		$html     = ( new FixReviewPage() )->html( $proposal, 'abc', 'https://example.test/wp-admin/admin-post.php', true, true, 1100 );
		self::assertStringContainsString( 'Off', $html );
		self::assertStringContainsString( 'Observe only', $html );
		self::assertStringContainsString( 'name="confirm" value="1"', $html );
		self::assertStringNotContainsString( 'name="password"', $html );
		self::assertStringNotContainsString( '<script>', $html );
	}

	public function test_block_approval_needs_https_and_current_password(): void {
		$proposal = new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-block', 'observe', 'block', 7, 1000, 1900 );
		self::assertFalse( FixApprovalAction::passwordConfirmed( $proposal, false, 'correct', static fn(): bool => true ) );
		self::assertFalse( FixApprovalAction::passwordConfirmed( $proposal, true, 'wrong', static fn(): bool => false ) );
		self::assertTrue( FixApprovalAction::passwordConfirmed( $proposal, true, 'correct', static fn(): bool => true ) );
		$html = ( new FixReviewPage() )->html( $proposal, 'abc', 'http://example.test/wp-admin/admin-post.php', false, true, 1100 );
		self::assertStringNotContainsString( 'name="confirm" value="1"', $html );
		self::assertStringContainsString( 'HTTPS', $html );
	}

	public function test_applied_change_can_be_rolled_back_after_mcp_opt_out_and_shows_failed_recheck(): void {
		$proposal = new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-observe', 'off', 'observe', 7, 1000, 1900, 'applied', 7, 1200 );
		$html     = ( new FixReviewPage() )->html( $proposal, 'approve', 'https://example.test/wp-admin/admin-post.php', true, false, 1300, 'rollback', 'pending' );
		self::assertStringContainsString( 'applied but could not be verified', $html );
		self::assertStringContainsString( '<dt>Previous</dt>', $html );
		self::assertStringContainsString( '<dt>Applied</dt>', $html );
		self::assertStringContainsString( 'name="action" value="amsec_fix_rollback"', $html );
		self::assertStringNotContainsString( 'name="action" value="amsec_fix_approve"', $html );
	}

	public function test_stale_live_setting_is_visible_and_cannot_be_approved(): void {
		$proposal = new FixProposal( str_repeat( 'a', 32 ), str_repeat( 'b', 32 ), 'login-rate-observe', 'off', 'observe', 7, 1000, 1900 );
		$html = ( new FixReviewPage() )->html( $proposal, 'abc', 'https://example.test/wp-admin/admin-post.php', true, true, 1100, '', '', 'block' );
		self::assertStringContainsString( 'The setting changed since this proposal was created', $html );
		self::assertStringContainsString( '<dt>Current</dt><dd>Block repeated failures</dd>', $html );
		self::assertStringNotContainsString( 'name="action" value="amsec_fix_approve"', $html );
	}
}
