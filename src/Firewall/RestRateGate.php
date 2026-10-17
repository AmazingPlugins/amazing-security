<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Login\AddressKey;
use Closure;
use WeakMap;

final class RestRateGate {
	private readonly Closure $counter;
	private WeakMap $seen;
	public function __construct( private readonly string $salt, callable $counter ) {
		$this->counter = Closure::fromCallable( $counter );
		$this->seen    = new WeakMap();}
	public function reject( object $request, ?array $state, string $route, string $method, bool $authenticated, mixed $prior, array $server, int $now ): bool {
		$p  = new RestRatePolicy();
		$id = $p->target( $route, $method, $authenticated, $prior );
		if ( null === $state || null === $id || 'off' === $state['mode'] || in_array( $id, $state['exemptions'], true ) ) {
			return false;}
		if ( isset( $this->seen[ $request ] ) ) {
			$old = $this->seen[ $request ];
			return $old['revision'] === $state['revision'] && $old['id'] === $id ? $old['reject'] : false;}
		if ( count( $this->seen ) >= 100 ) {
			return false;}
		$key    = ( new AddressKey( $this->salt . ':rest-rate:' . $state['revision'] . ':' . $id ) )->fromServer( $server );
		$reject = false;
		if ( null !== $key ) {
			try {
				$count      = ( $this->counter )( $key, 300, $now );
					$reject = $p->reject( $state['mode'], $id, $state['exemptions'], is_int( $count ) && $count >= 0 ? $count : null );
			} catch ( \Throwable ) {
				$reject = false;}
		}
		$this->seen[ $request ] = array(
			'revision' => $state['revision'],
			'id'       => $id,
			'reject'   => $reject,
		);
		return $reject;
	}
}
