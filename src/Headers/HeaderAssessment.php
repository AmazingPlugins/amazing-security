<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

final class HeaderAssessment {
	public const NAMES = array(
		'hsts'            => 'strict-transport-security',
		'content_type'    => 'x-content-type-options',
		'framing'         => 'x-frame-options',
		'referrer'        => 'referrer-policy',
		'csp'             => 'content-security-policy',
		'csp_report_only' => 'content-security-policy-report-only',
	);
	public function unknown(): array {
		return array(
			'state'   => 'unknown',
			'headers' => array_fill_keys( array_keys( self::NAMES ), 'unknown' ),
		);}
	public function valid( array $r ): bool {
		if ( array_keys( $r ) !== array( 'state', 'headers' ) || ! in_array( $r['state'], array( 'unknown', 'assessed' ), true ) || ! is_array( $r['headers'] ) || array_keys( $r['headers'] ) !== array_keys( self::NAMES ) ) {
			return false;}
		foreach ( $r['headers'] as $key => $value ) {
			$allowed = match ( $key ) {
				'hsts'=>array( 'missing', 'positive', 'disabled', 'ineffective', 'review' ), 'csp', 'csp_report_only'=>array( 'missing', 'present', 'review' ), default=>array( 'missing', 'recognized', 'review' )};
			if ( ! in_array( $value, 'unknown' === $r['state'] ? array( 'unknown' ) : $allowed, true ) ) {
				return false;}
		}
		return true;
	}
	public function parse( int $code, array $headers, bool $tls ): array {
		if ( 200 !== $code || count( $headers ) > 64 ) {
			return $this->unknown();}
		foreach ( array_merge( array( 'content-type' ), array_values( self::NAMES ) ) as $name ) {
			$values = $headers[ $name ] ?? array();
			if ( ! is_array( $values ) || ! array_is_list( $values ) || count( $values ) > 64 ) {
				return $this->unknown();
			}foreach ( $values as $v ) {
				if ( ! is_string( $v ) || strlen( $v ) > 2048 || preg_match( '/[\x00-\x08\x0A-\x1F\x7F]/', $v ) ) {
					return $this->unknown();}
			}
		}
		$type = $headers['content-type'] ?? array();
		if ( count( $type ) !== 1 || ! preg_match( '~^text/html(?:\s*;|\s*$)~i', $type[0] ) ) {
			return $this->unknown();}
		$r = array(
			'state'   => 'assessed',
			'headers' => array(),
		);
		foreach ( self::NAMES as $key => $name ) {
			$v     = $headers[ $name ] ?? array();
			$state = 'missing';
			if ( count( $v ) > 1 ) {
				$state = 'review';
			} elseif ( count( $v ) === 1 ) {
				$text      = strtolower( trim( $v[0] ) );
					$state = match ( $key ) {
					'hsts'=>$this->hsts( $text, $tls ), 'content_type'=>'nosniff' === $text ? 'recognized' : 'review', 'framing'=>in_array( $text, array( 'deny', 'sameorigin' ), true ) ? 'recognized' : 'review', 'referrer'=>$this->referrer( $text ) ? 'recognized' : 'review', default=>'' !== $text ? 'present' : 'review'};
			}$r['headers'][ $key ] = $state;}
		return $r;
	}
	private function hsts( string $v, bool $tls ): string {
		if ( ! $tls ) {
			return 'ineffective';}
		if ( ! preg_match( '/^max-age\s*=\s*([0-9]{1,12})(?:\s*;\s*(?:includesubdomains|preload))*\s*;?$/D', $v, $m ) ) {
			return 'review';}
		$directives = array_filter( array_map( 'trim', explode( ';', $v ) ) );
		if ( count( $directives ) !== count( array_unique( $directives ) ) ) {
			return 'review'; }
		return 0 === (int) $m[1] ? 'disabled' : 'positive';
	}
	private function referrer( string $v ): bool {
		foreach ( explode( ',', $v ) as $token ) {
			if ( ! in_array( trim( $token ), array( 'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url' ), true ) ) {
				return false;
			}
		}return true;
	}
}
