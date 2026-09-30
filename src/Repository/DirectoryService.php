<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use Closure;
final class DirectoryService {
	private mixed $raw = null;
	private readonly Closure $inventory;
	public function __construct( private readonly OptionGateway $options, private readonly DirectoryClient $client, callable $inventory ) {
		$this->inventory = Closure::fromCallable( $inventory );}
	public function status(): array {
		$this->raw = $this->options->get( 'amsec_repository_state' );
		if ( null === $this->raw ) {
			return array(
				'version' => 1,
				'records' => array(),
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded option validation.
		$state = is_string( $this->raw ) && strlen( $this->raw ) <= 131072 ? json_decode( $this->raw, true ) : null;
		if ( ! is_array( $state ) || array_keys( $state ) !== array( 'version', 'records' ) || 1 !== $state['version'] || ! is_array( $state['records'] ) || count( $state['records'] ) > 100 ) {
			return array( 'invalid' => true );}
		$parser = new DirectoryRecord();
		foreach ( $state['records'] as $key => $row ) {
			if ( ! is_string( $key ) || ! preg_match( '/^[a-f0-9]{32}$/D', $key ) || ! is_array( $row ) || array_keys( $row ) !== array( 'slug', 'installed_version', 'fingerprint', 'checked_at', 'result', 'last_closed' ) || ! is_string( $row['slug'] ) || strlen( $row['slug'] ) > 64 || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $row['slug'] ) || ! is_string( $row['installed_version'] ) || strlen( $row['installed_version'] ) > 64 || ! is_string( $row['fingerprint'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $row['fingerprint'] ) || ! is_int( $row['checked_at'] ) || $row['checked_at'] < 0 || ! is_array( $row['result'] ) || ! $parser->valid( $row['result'], $row['checked_at'] ) ) {
				return array( 'invalid' => true );}
			$old = $row['last_closed'];
			if ( 'closed' === $row['result']['state'] && array(
				'checked_at' => $row['checked_at'],
				'result'     => $row['result'],
			) !== $old ) {
				return array( 'invalid' => true );
			}
			if ( null !== $old && ( ! is_array( $old ) || array_keys( $old ) !== array( 'checked_at', 'result' ) || ! is_int( $old['checked_at'] ) || $old['checked_at'] < 0 || $old['checked_at'] > $row['checked_at'] || ! is_array( $old['result'] ) || 'closed' !== ( $old['result']['state'] ?? null ) || ! $parser->valid( $old['result'], $old['checked_at'] ) ) ) {
				return array( 'invalid' => true );}
		}
		return $state;
	}
	public function lookup( string $key, string $fingerprint, int $now ): string {
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $key ) || ! preg_match( '/^[a-f0-9]{64}$/D', $fingerprint ) || $now < 0 ) {
			return 'changed';}
		$lock = new WorkerLock( $this->options, 'amsec_repository_lock' );
		if ( ! $lock->acquire( 'repository-lookup' ) ) {
			return 'busy';}
		try {
			$state = $this->status();
			if ( ! empty( $state['invalid'] ) ) {
				return 'invalid';
			}$item = ( $this->inventory )( $key );
			if ( ! is_array( $item ) || ( $item['fingerprint'] ?? null ) !== $fingerprint ) {
				return 'changed';}
			if ( true !== ( $item['supported'] ?? false ) || ! is_string( $item['slug'] ?? null ) || strlen( $item['slug'] ) > 64 || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $item['slug'] ) || ! is_string( $item['version'] ?? null ) || strlen( $item['version'] ) > 64 ) {
				return 'unsupported';}
			$old = $state['records'][ $key ] ?? null;
			if ( null !== $old && $old['checked_at'] > $now ) {
				return 'failed';
			}
			if ( null === $old && count( $state['records'] ) >= 100 ) {
				return 'full';}
			if ( null !== $old && $old['fingerprint'] === $fingerprint && $old['checked_at'] <= $now && $now - $old['checked_at'] < 600 ) {
				return 'cached';}
			$parser = new DirectoryRecord();
			try {
				$result = $this->client->fetch( $item['slug'], $now );
			} catch ( \Throwable ) {
				$result = $parser->unknown();}
			if ( ! $parser->valid( $result, $now ) ) {
				$result = $parser->unknown();}
			$current = ( $this->inventory )( $key );
			if ( $current !== $item ) {
				return 'changed';}
			$lastClosed = null !== $old && $old['slug'] === $item['slug'] ? $old['last_closed'] : null;
			if ( 'closed' === $result['state'] ) {
				$lastClosed = array(
					'checked_at' => $now,
					'result'     => $result,
				);}
			$state['records'][ $key ] = array(
				'slug'              => $item['slug'],
				'installed_version' => $item['version'],
				'fingerprint'       => $fingerprint,
				'checked_at'        => $now,
				'result'            => $result,
				'last_closed'       => $lastClosed,
			);
	  // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure bounded option serialization.
			$encoded = json_encode( $state, JSON_THROW_ON_ERROR );
			if ( strlen( $encoded ) > 131072 ) {
				return 'full';}
			$saved = null === $this->raw ? $this->options->add( 'amsec_repository_state', $encoded ) : $this->options->replaceIfSame( 'amsec_repository_state', $this->raw, $encoded );
			return $saved ? 'saved' : 'failed';
		} finally {
			$lock->release();}
	}
}
