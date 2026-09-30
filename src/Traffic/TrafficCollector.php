<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

final class TrafficCollector {
	private bool $knownAdministrator = false;
	private bool $finished           = false;
	private string $decision         = 'unclassified';
	private ?string $route           = null;
	public function __construct( private readonly ?array $initial, private readonly array $server, private readonly bool $cli, private readonly bool $cron ) {}
	public function identifyAdministrator( bool $administrator ): void {
		$this->knownAdministrator = $this->knownAdministrator || $administrator; }
	public function decision( string $label ): void {
		if ( in_array( $label, TrafficEvent::DECISIONS, true ) && 'unclassified' !== $label ) {
			$this->decision = $label; } }
	public function restRoute( string $route ): void {
		$this->route = strlen( $route ) <= 2048 ? $route : ''; }
	public function finish( ?array $current, bool $administrator, int $status, int $now ): ?TrafficEvent {
		if ( $this->finished ) {
			return null; }
		$this->finished = true;
		if ( $this->cli || $this->cron || $administrator || $this->knownAdministrator || null === $this->initial || null === $current || ! $this->initial['enabled'] || ! $current['enabled'] || $this->initial['revision'] !== $current['revision'] ) {
			return null; }
		return TrafficEvent::capture( $this->server, $this->route, $status, $this->decision, $now );
	}
}
