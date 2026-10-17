<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\OptionGateway;
final class PasskeySettingsService {
	public function __construct( private readonly OptionGateway $options ) {}
	public function status(): array {
		return ( new PasskeyPolicy() )->read( $this->options->get( PasskeyPolicy::OPTION ) ) ?? array( 'invalid' => true );
	}
	public function fingerprint(): string {
		return ( new PasskeyPolicy() )->fingerprint( $this->options->get( PasskeyPolicy::OPTION ) );
	}
	public function apply( string $expected, bool $enabled, ?PasskeyContext $context ): string {
		$raw    = $this->options->get( PasskeyPolicy::OPTION );
		$parser = new PasskeyPolicy();
		if ( null === $parser->read( $raw ) ) {
			return 'invalid'; }
		if ( ! hash_equals( $parser->fingerprint( $raw ), $expected ) ) {
			return 'changed'; }
		if ( $enabled && ( null === $context || ! PasskeyVerifier::available() ) ) {
			return 'unavailable'; }
		$newRaw  = $this->policy( $enabled );
		$written = null === $raw ? $this->options->add( PasskeyPolicy::OPTION, $newRaw ) : $this->options->replaceIfSame( PasskeyPolicy::OPTION, $raw, $newRaw );
		return $written && $this->options->get( PasskeyPolicy::OPTION ) === $newRaw ? 'saved' : 'failed';
	}
	public function disable(): bool {
		$raw = $this->policy( false );
		return $this->options->set( PasskeyPolicy::OPTION, $raw ) && $this->options->get( PasskeyPolicy::OPTION ) === $raw;
	}
	private function policy( bool $enabled ): string {
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Exact pure local policy; every save invalidates old pending operations.
		return json_encode(
			array(
				'version'  => 1,
				'enabled'  => $enabled,
				'revision' => bin2hex( random_bytes( 16 ) ),
			),
			JSON_THROW_ON_ERROR
		);
	}
}
