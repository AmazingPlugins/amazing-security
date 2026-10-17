<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

/** Structural preflight for the supported WebAuthn profile, not a signature verifier. */
final class BoundedCbor {
	private string $bytes = '';
	private int $cursor   = 0;
	private int $items    = 0;
	public function read( string $bytes, int $offset = 0, bool $requireEnd = true ): ?array {
		if ( strlen( $bytes ) > 32768 || $offset < 0 || $offset >= strlen( $bytes ) ) {
			return null; }
		$this->bytes  = $bytes;
		$this->cursor = $offset;
		$this->items  = 0;
		try {
			$node = $this->node( 0 );
			if ( $requireEnd && strlen( $bytes ) !== $this->cursor ) {
				return null; }
			return array(
				'node'     => $node,
				'consumed' => $this->cursor - $offset,
			);
		} catch ( \RuntimeException $error ) {
			return null; }
	}
	private function take( int $length ): string {
		if ( $length < 0 || $length > strlen( $this->bytes ) - $this->cursor ) {
			throw new \RuntimeException( 'Invalid CBOR length.' ); }
		$value         = substr( $this->bytes, $this->cursor, $length );
		$this->cursor += $length;
		return $value;
	}
	private function argument( int $extra ): int {
		if ( $extra < 24 ) {
			return $extra; }
		$length = match ( $extra ) {
			24 => 1, 25 => 2, 26 => 4, default => 0 };
		if ( 0 === $length ) {
			throw new \RuntimeException( 'Unsupported CBOR argument.' ); }
		$value = 0;
		foreach ( str_split( $this->take( $length ) ) as $byte ) {
			$value = $value * 256 + ord( $byte ); }
		return $value;
	}
	private function node( int $depth ): array {
		if ( $depth > 8 || ++$this->items > 256 ) {
			throw new \RuntimeException( 'CBOR budget exceeded.' ); }
		$head  = ord( $this->take( 1 ) );
		$major = $head >> 5;
		$extra = $head & 31;
		if ( 7 === $major ) {
			return match ( $extra ) {
				20 => array(
					'type'  => 'boolean',
					'value' => false,
				), 21 => array(
					'type'  => 'boolean',
					'value' => true,
				), 22 => array(
					'type'  => 'null',
					'value' => null,
				), default => throw new \RuntimeException( 'Unsupported CBOR simple value.' ) };
		}
		if ( $major > 5 ) {
			throw new \RuntimeException( 'Unsupported CBOR type.' ); }
		$length = $this->argument( $extra );
		if ( $major < 2 ) {
			return array(
				'type'  => 'integer',
				'value' => 0 === $major ? $length : -1 - $length,
			); }
		if ( $major < 4 ) {
			$value = $this->take( $length );
			if ( 3 === $major && 1 !== preg_match( '//u', $value ) ) {
				throw new \RuntimeException( 'Invalid CBOR text.' ); }
			return array(
				'type'  => 2 === $major ? 'bytes' : 'text',
				'value' => $value,
			);
		}
		if ( $length > intdiv( 256 - $this->items, 5 === $major ? 2 : 1 ) ) {
			throw new \RuntimeException( 'CBOR item budget exceeded.' ); }
		$values = array();
		$seen   = array();
		for ( $i = 0; $i < $length; ++$i ) {
			$key = $this->node( $depth + 1 );
			if ( 4 === $major ) {
				$values[] = $key;
				continue; }
			if ( ! in_array( $key['type'], array( 'integer', 'text' ), true ) ) {
				throw new \RuntimeException( 'Unsupported CBOR map key.' ); }
			$identity = $key['type'] . ':' . $key['value'];
			if ( isset( $seen[ $identity ] ) ) {
				throw new \RuntimeException( 'Duplicate CBOR map key.' ); }
			$seen[ $identity ] = true;
			$values[]          = array(
				'key'   => $key,
				'value' => $this->node( $depth + 1 ),
			);
		}
		return array(
			'type'  => 4 === $major ? 'array' : 'map',
			'value' => $values,
		);
	}
}
