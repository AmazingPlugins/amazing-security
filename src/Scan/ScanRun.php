<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use DateTimeImmutable;

final class ScanRun {
	/** @param CheckResult[] $results */
	public function __construct( public readonly DateTimeImmutable $startedAt, public readonly DateTimeImmutable $finishedAt, public readonly array $results, public readonly bool $partial ) {}

	public function unknownCount(): int {
		return count( array_filter( $this->results, static fn( CheckResult $result ): bool => State::UNKNOWN === $result->state ) );
	}

	public function toArray(): array {
		return array(
			'started_at'  => $this->startedAt->format( 'c' ),
			'finished_at' => $this->finishedAt->format( 'c' ),
			'partial'     => $this->partial,
			'results'     => array_map( static fn( CheckResult $result ): array => $result->toArray(), $this->results ),
		);
	}

	public static function fromArray( array $data ): self {
		return new self( new DateTimeImmutable( $data['started_at'] ), new DateTimeImmutable( $data['finished_at'] ), array_map( array( CheckResult::class, 'fromArray' ), $data['results'] ), (bool) $data['partial'] );
	}
}
