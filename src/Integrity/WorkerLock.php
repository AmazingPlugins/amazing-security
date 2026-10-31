<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class WorkerLock {
	private const OPTION       = 'amsec_security_scanner_integrity_worker_lock';
	private ?string $heldValue = null;

	public function __construct( private readonly OptionGateway $options, private readonly string $optionKey = self::OPTION ) {}

	public function acquire( string $scanId ): bool {
		if ( ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $scanId ) ) {
			return false;
		}
		$previous = $this->options->get( $this->optionKey );
		if ( null !== $previous ) {
			$data = is_string( $previous ) ? json_decode( $previous, true ) : $previous;
			if ( is_array( $data ) && (int) ( $data['expires'] ?? 0 ) >= time() ) {
				return false;
			}
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Compare an older WordPress-serialized array lock without decoding arbitrary input.
			$expected = is_string( $previous ) ? $previous : serialize( $previous );
			if ( ! $this->options->deleteIfSame( $this->optionKey, $expected ) ) {
				return false;
			}
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- The lock is exercised in pure PHP tests.
		$value = json_encode(
			array(
				'scan_id' => $scanId,
				'expires' => time() + 60,
			),
			JSON_THROW_ON_ERROR
		);
		if ( ! $this->options->add( $this->optionKey, $value ) ) {
			return false;
		}
		$this->heldValue = $value;
		return true;
	}

	public function release(): void {
		if ( null !== $this->heldValue ) {
			$this->options->deleteIfSame( $this->optionKey, $this->heldValue );
			$this->heldValue = null;
		}
	}
}
