<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class RestFirewall {
	public function __construct( private readonly RequestInspector $inspector, private readonly ObservationStore $store ) {}

	public function observe( array $query, bool $authenticated, int $now, array $body = array() ): array {
		$queryResult = $this->inspector->inspect( $query, $authenticated );
		if ( $authenticated ) {
			return $queryResult;
		}
		$bodyResult = $this->inspector->inspect( $body, false );
		$rules      = array_values( array_unique( array_merge( $queryResult['rules'], $bodyResult['rules'] ) ) );
		$partial    = 'partial' === $queryResult['state'] || 'partial' === $bodyResult['state'];
		if ( array() !== $rules ) {
			$this->store->record( $rules, $now );
		}
		return array(
			'state' => $partial ? 'partial' : ( array() === $rules ? 'pass' : 'observe' ),
			'rules' => $rules,
		);
	}
}
