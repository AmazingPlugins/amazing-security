<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Admin\McpSettingsAction;
use AmazingPlugins\Security\Admin\McpSettingsRenderer;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Mcp\McpPreferences;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class McpPreferencesTest extends TestCase {
	public function test_default_off_and_explicit_toggle(): void {
		$options = $this->options();
		$prefs   = new McpPreferences( $options );
		self::assertFalse( $prefs->enabled() );
		$prefs->setEnabled( true );
		self::assertTrue( $prefs->enabled() );
		$prefs->setEnabled( false );
		self::assertFalse( $prefs->enabled() );
	}

	public function test_failed_write_never_claims_enabled(): void {
		$options = $this->options();
		$options->fail = true;
		$this->expectException( RuntimeException::class );
		( new McpPreferences( $options ) )->setEnabled( true );
	}

	public function test_action_rejects_nonliteral_switch_values(): void {
		self::assertTrue( McpSettingsAction::parse( array( 'enabled' => '1' ) ) );
		self::assertFalse( McpSettingsAction::parse( array( 'enabled' => '0' ) ) );
		$this->expectException( InvalidArgumentException::class );
		McpSettingsAction::parse( array( 'enabled' => 'yes' ) );
	}

	public function test_renderer_explains_support_and_escapes_form_values(): void {
		$view = ( new McpSettingsRenderer() )->render( false, false, false, 'https://example.invalid/admin-post.php', 'bad"><script>' );
		self::assertStringContainsString( 'WordPress 6.9', $view );
		self::assertStringContainsString( 'MCP Adapter', $view );
		self::assertStringNotContainsString( '<script>', $view );
		self::assertStringContainsString( 'disabled', $view );
	}

	private function options(): OptionGateway {
		return new class implements OptionGateway {
			public array $values = array();
			public bool $fail = false;
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( $this->fail ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { if ( $this->fail ) { return false; } $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { return false; }
			public function deleteIfSame( string $key, string $expected ): bool { return false; }
		};
	}
}
