<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\{OptionGateway, WorkerLock};
use Closure;

final class HeaderService {
	private mixed $raw = null;
	private readonly Closure $home;
	public function __construct( private readonly OptionGateway $options, private readonly HeaderClient $client, callable $home ) {
		$this->home = Closure::fromCallable( $home );}
	public function fingerprint(): string {
		$home = ( $this->home )();
		return is_string( $home ) ? hash( 'sha256', $home ) : ''; }
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_headers_state' );
		if ( null === $this->raw ) {
			return array(
				'version'   => 1,
				'latest'    => null,
				'last_good' => null,
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded state validation.
		$s = is_string( $this->raw ) && strlen( $this->raw ) <= 8192 ? json_decode( $this->raw, true ) : null;
		if ( ! is_array( $s ) || array_keys( $s ) !== array( 'version', 'latest', 'last_good' ) || 1 !== $s['version'] || ! $this->row( $s['latest'] ) || ( null !== $s['last_good'] && ! $this->row( $s['last_good'] ) ) ) {
			return array( 'invalid' => true );}
		if ( null !== $s['last_good'] && ( 'assessed' !== $s['last_good']['result']['state'] || $s['last_good']['captured_at'] > $s['latest']['captured_at'] ) ) {
			return array( 'invalid' => true );}
		if ( 'assessed' === $s['latest']['result']['state'] && $s['last_good'] !== $s['latest'] ) {
			return array( 'invalid' => true );}
		return $s;
	}
	private function row( mixed $r ): bool {
		return is_array( $r ) && array_keys( $r ) === array( 'fingerprint', 'captured_at', 'result' ) && is_string( $r['fingerprint'] ) && 1 === preg_match( '/^[a-f0-9]{64}$/D', $r['fingerprint'] ) && is_int( $r['captured_at'] ) && $r['captured_at'] >= 0 && is_array( $r['result'] ) && ( new HeaderAssessment() )->valid( $r['result'] );}
	public function check( string $fingerprint, int $now ): string {
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/D', $fingerprint ) || $now < 0 ) {
			return 'changed';}
		$lock = new WorkerLock( $this->options, 'amsec_headers_lock' );
		if ( ! $lock->acquire( 'header-assessment' ) ) {
			return 'busy';}
		try {
			$s = $this->status();
			if ( ! empty( $s['invalid'] ) ) {
				return 'invalid';}
			$home = ( $this->home )();
			if ( ! is_string( $home ) || hash( 'sha256', $home ) !== $fingerprint ) {
				return 'changed';}
			$old = $s['latest'];
			if ( null !== $old && $now < $old['captured_at'] ) {
				return 'failed';
			}if ( null !== $old && $old['fingerprint'] === $fingerprint && $now - $old['captured_at'] < 600 ) {
				return 'cached';}
			$parser = new HeaderAssessment();
			try {
				$result = $this->client->fetch( $home );
			} catch ( \Throwable ) {
				$result = $parser->unknown();
			}if ( ! $parser->valid( $result ) ) {
				$result = $parser->unknown();}
			if ( ( $this->home )() !== $home ) {
				return 'changed';}
			$s['latest'] = array(
				'fingerprint' => $fingerprint,
				'captured_at' => $now,
				'result'      => $result,
			);
			if ( 'assessed' === $result['state'] ) {
				$s['last_good'] = $s['latest'];}
	  // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure bounded normalized result serialization.
			$encoded = json_encode( $s, JSON_THROW_ON_ERROR );
			if ( strlen( $encoded ) > 8192 ) {
				return 'failed';}
			$saved = null === $this->raw ? $this->options->add( 'amsec_headers_state', $encoded ) : $this->options->replaceIfSame( 'amsec_headers_state', $this->raw, $encoded );
			return $saved ? 'saved' : 'failed';
		} finally {
			$lock->release();}
	}
}
