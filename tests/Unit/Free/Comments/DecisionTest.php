<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Comments;

require_once dirname( __DIR__, 4 ) . '/src/Free/Comments/Decision.php';

use AmazingPlugins\Security\Free\Comments\Decision;
use PHPUnit\Framework\TestCase;

/**
 * Decision tests. They do not bootstrap WordPress or touch the network.
 */
final class DecisionTest extends TestCase {
	public function test_option_defaults_off(): void {
		self::assertSame( 'amsec_comment_honeypot', Decision::OPTION );
		self::assertSame( '0', Decision::flag( null ) );
		self::assertSame( '0', Decision::flag( false ) );
		self::assertSame( '0', Decision::flag( '0' ) );
		self::assertSame( '0', Decision::flag( 0 ) );
		self::assertSame( '1', Decision::flag( '1' ) );
	}

	public function test_off_allows_empty_and_filled_fields(): void {
		self::assertSame( 'allow', Decision::outcome( '0', '' ) );
		self::assertSame( 'allow', Decision::outcome( '0', 'https://spam.test' ) );
		self::assertSame( 'allow', Decision::outcome( Decision::flag( null ), 'bot' ) );
	}

	public function test_on_allows_an_empty_field_and_rejects_a_filled_one(): void {
		self::assertSame( 'allow', Decision::outcome( '1', '' ) );
		self::assertSame( 'allow', Decision::outcome( '1', " \t\n" ) );
		self::assertSame( 'reject', Decision::outcome( '1', 'https://spam.test' ) );
		self::assertSame( 'reject', Decision::outcome( '1', '0' ) );
		self::assertSame( 'reject', Decision::outcome( '1', ' 0 ' ) );
	}

	public function test_non_string_field_is_filled_only_when_the_check_is_on(): void {
		self::assertSame( 'filled', Decision::text( array( 'x' ) ) );
		self::assertSame( 'filled', Decision::text( null ) );
		self::assertSame( '', Decision::text( '   ' ) );
		self::assertSame( 'bot', Decision::text( ' bot ' ) );
		self::assertSame( 'reject', Decision::outcome( '1', array( 'x' ) ) );
		self::assertSame( 'allow', Decision::outcome( '0', array( 'x' ) ) );
	}

	public function test_the_decision_does_not_take_the_comment_body(): void {
		$method = new \ReflectionMethod( Decision::class, 'outcome' );
		$names  = array();
		foreach ( $method->getParameters() as $parameter ) {
			$names[] = $parameter->getName();
		}
		self::assertSame( array( 'enabled', 'honeypot' ), $names );

		$source = (string) file_get_contents( dirname( __DIR__, 4 ) . '/src/Free/Comments/Decision.php' );
		self::assertDoesNotMatchRegularExpression( '/\b(get_option|add_option|add_action|add_filter|wp_|curl_|fsockopen)\b/', $source );
		self::assertStringNotContainsString( 'comment_content', $source );
		self::assertStringNotContainsString( 'HTTP_USER_AGENT', $source );
		self::assertStringNotContainsString( 'HTTP_REFERER', $source );
	}
}
