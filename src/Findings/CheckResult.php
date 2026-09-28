<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Findings;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

final class CheckResult {
	public readonly string $checkId;
	public readonly string $state;
	public readonly string $summary;
	public readonly string $sourceUrl;
	public readonly DateTimeImmutable $testedAt;
	public readonly string $confidence;
	public readonly string $coverage;
	public readonly array $evidence;
	public readonly ?string $findingId;

	public function __construct( string $checkId, string $state, string $summary, string $sourceUrl, DateTimeImmutable $testedAt, string $confidence, string $coverage, array $evidence, ?string $findingId = null ) {
		if ( ! State::isValid( $state ) ) {
			throw new InvalidArgumentException( 'Invalid finding state.' );
		}
		// Keep the value object usable in pure PHP unit tests without WordPress loaded.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		if ( ! preg_match( '/^[a-z][a-z0-9-]*$/', $checkId ) || ! filter_var( $sourceUrl, FILTER_VALIDATE_URL ) || ! in_array( strtolower( (string) parse_url( $sourceUrl, PHP_URL_SCHEME ) ), array( 'https' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid finding identifier or source.' );
		}
		if ( ! in_array( $confidence, array( 'high', 'medium', 'low' ), true ) || ! in_array( $coverage, array( 'complete', 'partial', 'unavailable' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid confidence or coverage.' );
		}
		foreach ( $evidence as $key => $value ) {
			if ( ! is_string( $key ) || ! preg_match( '/^[a-z][a-z0-9_]*$/', $key ) || ! ( is_scalar( $value ) || null === $value ) ) {
				throw new InvalidArgumentException( 'Evidence must contain metadata scalars only.' );
			}
		}
		if ( null !== $findingId && ! preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $findingId ) ) {
			throw new InvalidArgumentException( 'Invalid finding identity.' );
		}
		$this->checkId    = $checkId;
		$this->state      = $state;
		$this->summary    = $summary;
		$this->sourceUrl  = $sourceUrl;
		$this->testedAt   = $testedAt->setTimezone( new DateTimeZone( 'UTC' ) );
		$this->confidence = $confidence;
		$this->coverage   = $coverage;
		$this->evidence   = $evidence;
		$this->findingId  = $findingId;
	}

	public function toArray(): array {
		$data = array(
			'check_id'   => $this->checkId,
			'state'      => $this->state,
			'summary'    => $this->summary,
			'source_url' => $this->sourceUrl,
			'tested_at'  => $this->testedAt->format( 'c' ),
			'confidence' => $this->confidence,
			'coverage'   => $this->coverage,
			'evidence'   => $this->evidence,
		);
		if ( null !== $this->findingId ) {
			$data['finding_id'] = $this->findingId;
		}
		return $data;
	}

	public static function fromArray( array $value ): self {
		return new self( $value['check_id'], $value['state'], $value['summary'], $value['source_url'], new DateTimeImmutable( $value['tested_at'] ), $value['confidence'], $value['coverage'], $value['evidence'], $value['finding_id'] ?? null );
	}
}
