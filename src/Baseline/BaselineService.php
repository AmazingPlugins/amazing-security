<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

final class BaselineService {
	public function __construct( private readonly BaselineRepository $repository, private readonly ManifestBuilder $builder = new ManifestBuilder() ) {}

	public function preview( BaselineTarget $target, int $actor ): array {
		if ( $actor < 1 ) {
			throw new \RuntimeException( 'Administrator unavailable.' );
		}
		$stamp    = $target->stamp();
		$manifest = $this->builder->collect( $target->root, $target->singleFile );
		if ( array() === $manifest->files ) {
			throw new \RuntimeException( 'No covered source files to approve.' );
		}
		if ( ! hash_equals( $stamp, $target->stamp() ) ) {
			throw new \RuntimeException( 'Target changed.' );
		}
		list( $raw, $state )                  = $this->repository->snapshot();
		$state['previews']                    = array_filter( $state['previews'], static fn( array $p ): bool => $p['expires'] > time() );
		$key                                  = $target->key();
		$row                                  = array(
			'key'      => $key,
			'stamp'    => $stamp,
			'files'    => $manifest->files,
			'expires'  => time() + 300,
			'token'    => bin2hex( random_bytes( 16 ) ),
			'previous' => self::rowHash( $state['baselines'][ $key ] ?? null ),
		);
		$state['previews'][ (string) $actor ] = $row;
		$this->repository->save( $raw, $state );
		return $row;
	}

	public function approve( BaselineTarget $target, int $actor, string $token ): void {
		list( $raw, $state ) = $this->repository->snapshot();
		$preview             = $state['previews'][ (string) $actor ] ?? null;
		if ( ! is_array( $preview ) || $preview['expires'] <= time() || ! hash_equals( $preview['token'], $token ) || $preview['key'] !== $target->key() || ! hash_equals( $preview['stamp'], $target->stamp() ) || ! hash_equals( $preview['previous'], self::rowHash( $state['baselines'][ $target->key() ] ?? null ) ) ) {
			throw new \RuntimeException( 'Preview expired or target/reference changed.' );
		}
		$current = $this->builder->collect( $target->root, $target->singleFile );
		if ( ! hash_equals( ( new BaselineManifest( $preview['files'] ) )->fingerprint(), $current->fingerprint() ) || ! hash_equals( $preview['stamp'], $target->stamp() ) ) {
			throw new \RuntimeException( 'Covered files changed after preview.' );
		}
		$state['baselines'][ $target->key() ] = array(
			'key'         => $target->key(),
			'stamp'       => $preview['stamp'],
			'files'       => $current->files,
			'approved_at' => time(),
		);
		unset( $state['previews'][ (string) $actor ] );
		$this->repository->save( $raw, $state );
	}

	public function compare( BaselineTarget $target ): array {
		list( , $state ) = $this->repository->snapshot();
		$row             = $state['baselines'][ $target->key() ] ?? null;
		if ( ! is_array( $row ) || ! hash_equals( $row['stamp'], $target->stamp() ) ) {
			throw new \RuntimeException( 'Reference unavailable or target identity changed.' );
		}
		$current = $this->builder->collect( $target->root, $target->singleFile );
		if ( ! hash_equals( $row['stamp'], $target->stamp() ) ) {
			throw new \RuntimeException( 'Target changed during comparison.' );
		}
		return ( new BaselineManifest( $row['files'] ) )->compare( $current );
	}

	private static function rowHash( ?array $row ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Private compare-and-swap reference fingerprint.
		return hash( 'sha256', json_encode( $row, JSON_THROW_ON_ERROR ) );
	}
}
