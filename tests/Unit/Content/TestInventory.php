<?php
namespace AmazingPlugins\Security\Tests\Unit\Content;

use AmazingPlugins\Security\Content\ContentInventory;
final class TestInventory implements ContentInventory {
	public array $bodies     = array(
		'post'    => array(),
		'comment' => array(),
	);
	public bool $changed     = false;
	public bool $fail        = false;
	public mixed $duringRead = null;
	public function __construct( int $n = 1 ) {
		for ( $i = 1;$i <= $n;$i++ ) {
			$this->bodies['post'][ $i ] = '<a href="javascript:fixture">x</a>';}}
	public function bounds(): array {
		return array(
			'post'    => max( array_keys( $this->bodies['post'] ) ?: array( 0 ) ),
			'comment' => max( array_keys( $this->bodies['comment'] ) ?: array( 0 ) ),
		);}
	public function candidates( string $kind, int $after, int $max, int $limit ): array {
		if ( $this->fail ) {
			throw new \RuntimeException( 'fixture database failure' );
		}$out = array();
		foreach ( $this->bodies[ $kind ] as $id => $body ) {
			if ( $id > $after && $id <= $max ) {
				$out[] = array(
					'id'    => $id,
					'bytes' => strlen( $body ),
					'hash'  => hash( 'sha256', $body ),
				);
				if ( count( $out ) >= $limit ) {
					break;
				}
			}
		}return $out;}
	public function read( string $kind, int $id, string $hash ): ?string {
		if ( is_callable( $this->duringRead ) ) {
			( $this->duringRead )();
			$this->duringRead = null;
		}return $this->changed ? null : ( $this->bodies[ $kind ][ $id ] ?? null );}
}
