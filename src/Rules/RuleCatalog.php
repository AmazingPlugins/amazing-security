<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Rules;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Content\MarkupDetector;
use AmazingPlugins\Security\FileScan\BundledRulePack;
use AmazingPlugins\Security\Firewall\BundledRequestRules;
use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;

/** Local release metadata. It is not an independent authenticity or malware-feed check. */
final class RuleCatalog {
	public function __construct( private readonly string $root ) {}
	public static function descriptors(): array {
		return array(
			'files'    => array(
				'label'    => 'File review patterns',
				'version'  => ( new BundledRulePack() )->version(),
				'ids'      => array_keys( ( new BundledRulePack() )->rules() ),
				'files'    => array( 'src/FileScan/BundledRulePack.php', 'src/FileScan/RuleMatcher.php', 'src/FileScan/AdjacentFlow.php', 'src/FileScan/MalwareSignatures.php' ),
				'fixtures' => 'tests/Fixtures/FileScan/corpus.json',
				'scope'    => 'Selected PHP and inline-HTML patterns; broad malware detection remains incomplete.',
			),
			'content'  => array(
				'label'    => 'Published-content patterns',
				'version'  => MarkupDetector::VERSION,
				'ids'      => MarkupDetector::RULES,
				'files'    => array( 'src/Content/MarkupDetector.php' ),
				'fixtures' => 'tests/Unit/Content/MarkupTest.php',
				'scope'    => 'Selected public-content patterns; links are not contacted or checked against a reputation service.',
			),
			'requests' => array(
				'label'    => 'REST observation patterns',
				'version'  => ( new BundledRequestRules() )->version(),
				'ids'      => ( new BundledRequestRules() )->ids(),
				'files'    => array( 'src/Firewall/BundledRequestRules.php' ),
				'fixtures' => 'tests/Unit/Firewall/',
				'scope'    => 'Observe-only patterns with known benign matches; they must not be used as blocking rules.',
			),
		);
	}
	public function buildManifest( string $date ): array {
		if ( null === $this->date( $date ) ) {
			throw new RuntimeException( 'Invalid metadata review date.' );}
		$manifest = array(
			'schema' => 1,
			'packs'  => array(),
		);
		foreach ( self::descriptors() as $id => $pack ) {
			$hashes = array();
			foreach ( $pack['files'] as $file ) {
				$bytes = $this->read( $file, 262144 );
				if ( null === $bytes ) {
					throw new RuntimeException( 'Rule source unavailable.' );
				}$hashes[ $file ] = hash( 'sha256', $bytes );
			}$manifest['packs'][ $id ] = array(
				'version'     => $pack['version'],
				'reviewed_at' => $date,
				'ids'         => $pack['ids'],
				'sha256'      => $hashes,
			);}
		return $manifest;
	}
	public function status( int $now ): array {
		$bytes = $this->read( 'assets/rule-manifest.json', 32768 );
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure PHP local bounded manifest inspection.
		$manifest = null === $bytes ? null : json_decode( $bytes, true );
		$valid    = is_array( $manifest ) && 1 === ( $manifest['schema'] ?? null ) && is_array( $manifest['packs'] ?? null ) && array_keys( $manifest['packs'] ) === array_keys( self::descriptors() );
		$status   = array();
		foreach ( self::descriptors() as $id => $descriptor ) {
			$pack = $valid ? ( $manifest['packs'][ $id ] ?? null ) : null;
			$date = is_array( $pack ) && is_string( $pack['reviewed_at'] ?? null ) ? $this->date( $pack['reviewed_at'] ) : null;
			$ok   = is_array( $pack ) && ( $pack['version'] ?? null ) === $descriptor['version'] && ( $pack['ids'] ?? null ) === $descriptor['ids'] && is_array( $pack['sha256'] ?? null ) && array_keys( $pack['sha256'] ) === $descriptor['files'] && null !== $date && $date <= $now;
			if ( $ok ) {
				foreach ( $descriptor['files'] as $file ) {
					$source = $this->read( $file, 262144 );
					$hash   = $pack['sha256'][ $file ];
					if ( null === $source || ! is_string( $hash ) || ! preg_match( '/^[a-f0-9]{64}$/D', $hash ) || ! hash_equals( $hash, hash( 'sha256', $source ) ) ) {
						$ok = false;
						break;}
				}
			}
			$status[ $id ] = $descriptor + array(
				'status'      => $ok ? ( $now - $date >= 90 * 86400 ? 'overdue' : 'recent' ) : 'unknown',
				'reviewed_at' => $ok ? $pack['reviewed_at'] : '',
				'age_days'    => $ok ? (int) floor( ( $now - $date ) / 86400 ) : null,
				'origin'      => 'AmazingPlugins authored local review patterns',
				'license'     => 'GPL-2.0-or-later',
				'owner'       => 'AmazingPlugins',
			);
		}
		return $status;
	}
	private function date( string $value ): ?int {
		if ( ! preg_match( '/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/D', $value ) ) {
			return null;
		}
		$d = DateTimeImmutable::createFromFormat( '!Y-m-d', $value, new DateTimeZone( 'UTC' ) );
		return false !== $d && $d->format( 'Y-m-d' ) === $value ? $d->getTimestamp() : null;
	}
	private function read( string $relative, int $limit ): ?string {
		$root = realpath( $this->root );
		if ( false === $root ) {
			return null;
		}$path = $root . '/' . $relative;
		if ( is_link( $path ) || realpath( $path ) !== $path || ! is_file( $path ) ) {
			return null;}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- Suppress fixed-path read warnings and return unknown. Fixed, local regular files only; read budget enforced below.
		$handle = @fopen( $path, 'rb' );
		if ( false === $handle ) {
			return null;}
		try {
			$before = fstat( $handle );
			if ( false === $before || ( $before['mode'] & 0170000 ) !== 0100000 || $before['size'] > $limit ) {
				return null;}
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded local source read, never included or evaluated.
			$bytes = fread( $handle, $limit + 1 );
			$after = fstat( $handle );
			return false !== $bytes && strlen( $bytes ) <= $limit && strlen( $bytes ) === $before['size'] && array_intersect_key( $before, array_flip( array( 'dev', 'ino', 'mode', 'size', 'mtime', 'ctime' ) ) ) === array_intersect_key( ( false === $after ? array() : $after ), array_flip( array( 'dev', 'ino', 'mode', 'size', 'mtime', 'ctime' ) ) ) ? $bytes : null;
		} finally {
		 // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the bounded source handle.
			fclose( $handle );
		}
	}
}
