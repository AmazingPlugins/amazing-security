<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;

/** Reports a visible local rule without proving that uploads cannot run PHP. */
final class UploadsExecutionCheck implements SecurityCheck {
	private readonly ?Closure $readRule;

	public function __construct( ?callable $readRule = null ) {
		$this->readRule = null === $readRule ? null : Closure::fromCallable( $readRule );
	}

	public function id(): string {
		return 'uploads-php-execution';
	}

	public function run( ScanContext $context ): array {
		$rule    = $this->readRule instanceof Closure ? ( $this->readRule )() : self::visibleRule();
		$label   = is_string( $rule ) && in_array( $rule, array( 'engine-off', 'filesmatch-deny' ), true ) ? $rule : '';
		$summary = '' !== $label
			? 'A local uploads rule (' . $label . ') was found. That does not prove PHP is blocked. Ask your host how this server runs PHP. No test file was written.'
			: 'PHP in the uploads folder has not been checked on this server. Ask your host whether that folder can run PHP. No test file was written.';
		return array(
			new CheckResult(
				$this->id(),
				State::UNKNOWN,
				$summary,
				'https://developer.wordpress.org/advanced-administration/security/hardening/',
				new DateTimeImmutable(),
				'low',
				'unavailable',
				array(
					'method' => '' !== $label ? 'local_rule' : 'no_runtime_probe',
					'rule'   => '' !== $label ? $label : 'none',
				),
			),
		);
	}

	public static function classify( string $text ): string {
		if ( preg_match( '/php_(?:admin_)?flag\s+engine\s+off/i', $text ) ) {
			return 'engine-off';
		}
		if ( preg_match( '/<FilesMatch\b[^>]*php/i', $text ) && preg_match( '/Require\s+all\s+denied|Deny\s+from\s+all/i', $text ) ) {
			return 'filesmatch-deny';
		}
		return '';
	}

	private static function visibleRule(): string {
		if ( ! function_exists( 'wp_upload_dir' ) || ! defined( 'WP_CONTENT_DIR' ) ) {
			return '';
		}
		$upload     = wp_upload_dir( null, false );
		$candidates = array();
		if ( is_array( $upload ) && empty( $upload['error'] ) && is_string( $upload['basedir'] ?? null ) ) {
			$candidates[] = rtrim( $upload['basedir'], '/' ) . '/.htaccess';
		}
		$candidates[] = rtrim( WP_CONTENT_DIR, '/' ) . '/.htaccess';
		foreach ( $candidates as $path ) {
			$label = self::ruleIn( $path );
			if ( '' !== $label ) {
				return $label;
			}
		}
		return '';
	}

	private static function ruleIn( string $path ): string {
		$root = rtrim( WP_CONTENT_DIR, '/' );
		if ( strlen( $path ) > 4096 || str_contains( $path, "\0" ) || ! str_starts_with( $path, $root . '/' ) || is_link( $path ) || ! is_file( $path ) ) {
			return '';
		}
		$real = realpath( $path );
		if ( ! is_string( $real ) || ! str_starts_with( $real, $root . '/' ) ) {
			return '';
		}
		$size = filesize( $real );
		if ( ! is_int( $size ) || $size < 1 || $size > 65536 ) {
			return '';
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded local .htaccess read. No probe file is written.
		$text = file_get_contents( $real );
		return is_string( $text ) ? self::classify( $text ) : '';
	}
}
