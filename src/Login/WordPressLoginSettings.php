<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
use InvalidArgumentException;
use RuntimeException;

final class WordPressLoginSettings implements LoginSettings {
	public function __construct( private OptionGateway $options ) {}

	public function rateMode(): string {
		$mode = $this->options->get( 'amsec_login_rate_mode' );
		return in_array( $mode, array( 'off', 'observe', 'block' ), true ) ? $mode : 'off';
	}

	public function setRateMode( string $mode ): void {
		if ( ! in_array( $mode, array( 'off', 'observe', 'block' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid login rate mode.' );
		}
		$this->write( 'amsec_login_rate_mode', $mode );
	}

	public function xmlRpcAuthDisabled(): bool {
		return '1' === $this->options->get( 'amsec_login_xmlrpc_disabled' );
	}

	public function setXmlRpcAuthDisabled( bool $disabled ): void {
		$this->write( 'amsec_login_xmlrpc_disabled', $disabled ? '1' : '0' );
	}

	public function eraseOnUninstall(): bool {
		return '1' === $this->options->get( 'amsec_login_erase_on_uninstall' );
	}

	public function setEraseOnUninstall( bool $erase ): void {
		$this->write( 'amsec_login_erase_on_uninstall', $erase ? '1' : '0' );
	}

	private function write( string $key, string $value ): void {
		$current = $this->options->get( $key );
		if ( $current === $value ) {
			return;
		}
		$ok = null === $current ? $this->options->add( $key, $value ) : $this->options->set( $key, $value );
		if ( ! $ok ) {
			throw new RuntimeException( 'Could not save login setting.' );
		}
	}
}
