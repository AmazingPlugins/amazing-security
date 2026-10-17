<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

defined( 'ABSPATH' ) || exit;

/** Reject unsupported authenticator layouts before the upstream verifier parses them. */
final class AuthenticatorProfile {
	public function registration( string $attestation, string $expectedCredentialId ): ?array {
		$reader = new BoundedCbor();
		$parsed = $reader->read( $attestation );
		$map    = $this->map( $parsed['node'] ?? array(), 'text' );
		if ( null === $map || count( $map ) !== 3 || ( $map['fmt'] ?? null ) !== array(
			'type'  => 'text',
			'value' => 'none',
		) || ( $map['attStmt'] ?? null ) !== array(
			'type'  => 'map',
			'value' => array(),
		) || ( $map['authData']['type'] ?? null ) !== 'bytes' ) {
			return null; }
		$data = $map['authData']['value'];
		if ( strlen( $data ) < 55 || strlen( $data ) > 8192 ) {
			return null; }
		$flags = $this->flags( $data, true );
		if ( null === $flags ) {
			return null; }
		$length = ord( $data[53] ) * 256 + ord( $data[54] );
		if ( $length < 1 || $length > 1024 || strlen( $data ) < 55 + $length || ! hash_equals( $expectedCredentialId, substr( $data, 55, $length ) ) ) {
			return null; }
		$cose = $reader->read( $data, 55 + $length );
		$key  = $this->map( $cose['node'] ?? array(), 'integer' );
		if ( null === $key || count( $key ) !== 5 || ( $key[1] ?? null ) !== array(
			'type'  => 'integer',
			'value' => 2,
		) || ( $key[3] ?? null ) !== array(
			'type'  => 'integer',
			'value' => -7,
		) || ( $key[-1] ?? null ) !== array(
			'type'  => 'integer',
			'value' => 1,
		) ) {
			return null; }
		foreach ( array( -2, -3 ) as $coordinate ) {
			if ( ( $key[ $coordinate ]['type'] ?? null ) !== 'bytes' || strlen( $key[ $coordinate ]['value'] ) !== 32 ) {
				return null; }
		}
		return $flags + array( 'authenticator_data' => $data );
	}
	public function assertion( string $data ): ?array {
		if ( strlen( $data ) !== 37 ) {
			return null; }
		$flags = $this->flags( $data, false );
		return null === $flags ? null : $flags + array( 'authenticator_data' => $data );
	}
	private function flags( string $data, bool $registration ): ?array {
		$flags = ord( $data[32] );
		if ( ( $flags & 0x05 ) !== 0x05 || ( $flags & 0xa2 ) !== 0 || ( ( $flags & 0x40 ) !== 0 ) !== $registration || ( ( $flags & 0x10 ) !== 0 && ( $flags & 0x08 ) === 0 ) ) {
			return null; }
		$counter = 0;
		foreach ( str_split( substr( $data, 33, 4 ) ) as $byte ) {
			$counter = $counter * 256 + ord( $byte ); }
		return array(
			'counter'         => $counter,
			'backup_eligible' => ( $flags & 0x08 ) !== 0,
			'backed_up'       => ( $flags & 0x10 ) !== 0,
		);
	}
	private function map( array $node, string $keyType ): ?array {
		if ( ( $node['type'] ?? null ) !== 'map' ) {
			return null; }
		$map = array();
		foreach ( $node['value'] as $pair ) {
			if ( $pair['key']['type'] !== $keyType ) {
				return null; }
			$map[ $pair['key']['value'] ] = $pair['value'];
		}
		return $map;
	}
}
