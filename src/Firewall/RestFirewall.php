<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class RestFirewall {
	public function __construct( private readonly RequestInspector $inspector, private readonly ObservationStore $store ) {}

	public function observe( array $query, bool $authenticated, int $now ): array {
		$result = $this->inspector->inspect( $query, $authenticated );
		if ( array() !== $result['rules'] ) {
			$this->store->record( $result['rules'], $now );
		}
		return $result;
	}
}
