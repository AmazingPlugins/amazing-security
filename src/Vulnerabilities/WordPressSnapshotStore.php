<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\OptionGateway;
use RuntimeException;

final class WordPressSnapshotStore implements SnapshotStore {
	private const OPTION = 'amazing_security_vulnerability_snapshot';

	public function __construct( private readonly OptionGateway $options ) {}

	public function latestAccepted(): ?Snapshot {
		$value = $this->options->get( self::OPTION );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Stored data is local and bounded by verifier.
		$data = is_string( $value ) ? json_decode( $value, true ) : null;
		return is_array( $data ) ? Snapshot::fromArray( $data ) : null;
	}

	public function saveAccepted( SnapshotResult $result ): void {
		if ( 'accepted' !== $result->state || null === $result->snapshot ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure-PHP storage contract.
		$value    = json_encode( $result->snapshot->toArray(), JSON_THROW_ON_ERROR );
		$previous = $this->options->get( self::OPTION );
		if ( $previous === $value ) {
			return;
		}
		if ( null === $previous ? ! $this->options->add( self::OPTION, $value ) : ! $this->options->set( self::OPTION, $value ) ) {
			throw new RuntimeException( 'Could not save verified vulnerability snapshot.' );
		}
	}
}
