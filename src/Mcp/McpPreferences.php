<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Mcp;

use AmazingPlugins\Security\Integrity\OptionGateway;
use RuntimeException;

final class McpPreferences {
	private const ENABLED = 'amazing_security_mcp_enabled';

	public function __construct( private readonly OptionGateway $options ) {}

	public function enabled(): bool {
		return '1' === $this->options->get( self::ENABLED );
	}

	public function setEnabled( bool $enabled ): void {
		$old = $this->options->get( self::ENABLED );
		$new = $enabled ? '1' : '0';
		if ( $old === $new ) {
			return;
		}
		if ( ! ( null === $old ? $this->options->add( self::ENABLED, $new ) : $this->options->set( self::ENABLED, $new ) ) ) {
			throw new RuntimeException( 'Could not save MCP setting.' );
		}
	}
}
