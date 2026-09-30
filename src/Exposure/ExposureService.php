<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use Closure;
final class ExposureService {
	private mixed $raw = null;
	private readonly Closure $roots;
	public function __construct( private readonly OptionGateway $options, private readonly ExposureScanner $scanner, callable $roots ) {
		$this->roots = Closure::fromCallable( $roots );}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_exposure_state' );
		if ( null === $this->raw ) {
			return array(
				'version' => 1,
				'reports' => array(),
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded local report validation.
		$state = is_string( $this->raw ) && strlen( $this->raw ) <= 262144 ? json_decode( $this->raw, true ) : null;
		if ( ! is_array( $state ) || array_keys( $state ) !== array( 'version', 'reports' ) || 1 !== $state['version'] || ! is_array( $state['reports'] ) || count( $state['reports'] ) > 3 ) {
			return array( 'invalid' => true );}
		foreach ( $state['reports'] as $alias => $report ) {
			if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) || ! is_array( $report ) || ! $this->valid( $report, $alias ) ) {
				return array( 'invalid' => true );}
		}
		return $state;
	}
	public function scan( string $alias, int $now ): string {
		if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) || $now < 0 ) {
			return 'unsupported';}
		$lock = new WorkerLock( $this->options, 'amsec_exposure_lock' );
		if ( ! $lock->acquire( 'exposure-inventory' ) ) {
			return 'busy';}
		try {
			$state = $this->status();
			if ( ! empty( $state['invalid'] ) ) {
				return 'invalid';}
			$root   = ( $this->roots )( $alias );
			$report = $this->scanner->scan( is_string( $root ) ? $root : null, $alias, $now );
			if ( ! $this->valid( $report, $alias ) ) {
				return 'failed';
			}$state['reports'][ $alias ] = $report;
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure bounded local report serialization.
			$encoded = json_encode( $state, JSON_THROW_ON_ERROR );
			if ( strlen( $encoded ) > 262144 ) {
				return 'failed';}
			$saved = null === $this->raw ? $this->options->add( 'amsec_exposure_state', $encoded ) : $this->options->replaceIfSame( 'amsec_exposure_state', $this->raw, $encoded );
			return $saved ? 'saved' : 'failed';
		} finally {
			$lock->release();}
	}
	private function valid( array $r, string $alias ): bool {
		if ( array_keys( $r ) !== array( 'alias', 'captured_at', 'entries', 'directories', 'unknown', 'excluded', 'partial', 'reasons', 'candidates' ) || $r['alias'] !== $alias || ! is_bool( $r['partial'] ) || ! is_array( $r['reasons'] ) || ! is_array( $r['candidates'] ) || ! array_is_list( $r['reasons'] ) || ! array_is_list( $r['candidates'] ) || count( $r['candidates'] ) > 100 || count( $r['reasons'] ) > 8 || ( array() !== $r['reasons'] ) !== $r['partial'] || count( array_unique( $r['reasons'], SORT_REGULAR ) ) !== count( $r['reasons'] ) ) {
			return false;}
		foreach ( array(
			'captured_at' => PHP_INT_MAX,
			'entries'     => 1500,
			'directories' => 50,
			'unknown'     => 1600,
			'excluded'    => 1500,
		) as $key => $max ) {
			if ( ! is_int( $r[ $key ] ) || $r[ $key ] < 0 || $r[ $key ] > $max ) {
				return false;}
		}
		if ( count( $r['candidates'] ) > $r['entries'] || ( $r['entries'] > 0 && 0 === $r['directories'] ) || ( ! $r['partial'] && 0 === $r['directories'] ) || ( $r['unknown'] > 0 && ! $r['partial'] ) ) {
			return false;}
		foreach ( $r['reasons'] as $reason ) {
			if ( ! is_string( $reason ) || ! in_array( $reason, array( 'unknown_entries', 'depth_limit', 'entry_limit', 'directory_limit', 'candidate_limit', 'work_target', 'root_unavailable', 'root_changed' ), true ) ) {
				return false;}
		}
		$paths = array();
		foreach ( $r['candidates'] as $c ) {
			if ( ! is_array( $c ) || array_keys( $c ) !== array( 'alias', 'path', 'category', 'bytes', 'modified_at' ) || $c['alias'] !== $alias || ! is_string( $c['path'] ) || ! ExposureScanner::validPath( $c['path'] ) || isset( $paths[ $c['path'] ] ) || ! is_string( $c['category'] ) || ExposureScanner::classify( basename( $c['path'] ) ) !== $c['category'] || ! is_int( $c['bytes'] ) || $c['bytes'] < 0 || ! is_int( $c['modified_at'] ) || $c['modified_at'] < 0 || substr_count( $c['path'], '/' ) > ( 'uploads' === $alias ? 3 : 0 ) ) {
				return false;
			}$paths[ $c['path'] ] = true;}
		return true;
	}
}
