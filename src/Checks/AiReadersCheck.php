<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Checks;

use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use AmazingPlugins\Security\Scan\SecurityCheck;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/** Reports guest comments, registration, and AI crawler rules. It does not change them. */
final class AiReadersCheck implements SecurityCheck {
	private const SOURCE   = 'https://developer.wordpress.org/advanced-administration/security/hardening/';
	private const CRAWLERS = array( 'gptbot', 'chatgpt-user', 'claudebot', 'google-extended', 'ccbot', 'perplexitybot', 'applebot-extended', 'bytespider' );
	private readonly Closure $read;

	public function __construct( callable $read ) {
		$this->read = Closure::fromCallable( $read );
	}

	public function id(): string {
		return 'ai-readers';
	}

	public function run( ScanContext $context ): array {
		try {
			$snapshot = ( $this->read )();
		} catch ( Throwable ) {
			$snapshot = array();
		}
		if ( ! is_array( $snapshot ) ) {
			$snapshot = array();
		}
		$guest        = self::choice( $snapshot['guest_comments'] ?? null );
		$registration = self::choice( $snapshot['registration'] ?? null );
		$crawlers     = is_string( $snapshot['robots'] ?? null ) ? self::stance( $snapshot['robots'] ) : 'unknown';
		$state        = match ( true ) {
			'open' === $guest || 'open' === $registration => State::WARN,
			'closed' === $guest && 'closed' === $registration => State::PASS,
			default => State::UNKNOWN,
		};
		return array(
			new CheckResult(
				$this->id(),
				$state,
				self::summary( $guest, $registration, $crawlers ),
				self::SOURCE,
				new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ),
				State::UNKNOWN === $state ? 'low' : 'medium',
				State::UNKNOWN === $state ? 'unavailable' : 'complete',
				array(
					'guest_comments' => $guest,
					'registration'   => $registration,
					'ai_crawlers'    => $crawlers,
				)
			),
		);
	}

	/** @return array{guest_comments: string|null, registration: string|null, robots: string|null} */
	public static function wordpressSnapshot(): array {
		$status  = get_option( 'default_comment_status', null );
		$login   = get_option( 'comment_registration', null );
		$signups = get_option( 'users_can_register', null );
		$guest   = null;
		if ( 'closed' === $status || self::enabled( $login ) ) {
			$guest = 'closed';
		} elseif ( 'open' === $status ) {
			$guest = 'open';
		}
		$registration = null;
		if ( self::enabled( $signups ) ) {
			$registration = 'open';
		} elseif ( false === $signups || '' === $signups || '0' === $signups || 0 === $signups ) {
			$registration = 'closed';
		}
		return array(
			'guest_comments' => $guest,
			'registration'   => $registration,
			'robots'         => self::robotsBody(),
		);
	}

	public static function stance( string $body ): string {
		$groups  = self::groups( $body );
		$blocked = 0;
		foreach ( self::CRAWLERS as $crawler ) {
			if ( self::blocked( $groups, $crawler ) ) {
				++$blocked;
			}
		}
		if ( count( self::CRAWLERS ) === $blocked ) {
			return 'blocked';
		}
		return $blocked > 0 ? 'limited' : 'allowed';
	}

	private static function choice( mixed $value ): string {
		return is_string( $value ) && in_array( $value, array( 'open', 'closed' ), true ) ? $value : 'unknown';
	}

	private static function summary( string $guest, string $registration, string $crawlers ): string {
		$bots = match ( true ) {
			'open' === $guest && 'open' === $registration => __( 'Guests can comment on new posts, and anyone can register.', 'amazing-security' ),
			'open' === $guest && 'closed' === $registration => __( 'Guests can comment on new posts. Registration is closed.', 'amazing-security' ),
			'closed' === $guest && 'open' === $registration => __( 'Guests cannot comment on new posts, and anyone can register.', 'amazing-security' ),
			'closed' === $guest && 'closed' === $registration => __( 'Guests cannot comment on new posts, and registration is closed.', 'amazing-security' ),
			'open' === $guest => __( 'Guests can comment on new posts. The registration setting could not be read.', 'amazing-security' ),
			'open' === $registration => __( 'Anyone can register. The comment setting could not be read.', 'amazing-security' ),
			default => __( 'Comment or registration settings could not be read.', 'amazing-security' ),
		};
		$rules = match ( $crawlers ) {
			'allowed' => __( 'AI crawlers are not asked to stay out.', 'amazing-security' ),
			'limited' => __( 'Some AI crawlers are asked to stay out.', 'amazing-security' ),
			'blocked' => __( 'The crawler rules ask the main AI crawlers to stay out.', 'amazing-security' ),
			default => __( 'The crawler rules could not be read.', 'amazing-security' ),
		};
		return $bots . ' ' . $rules . ' This check does not change those settings. Author names stay available over the content API.';
	}

	private static function enabled( mixed $value ): bool {
		return true === $value || 1 === $value || '1' === $value;
	}

	private static function robotsBody(): ?string {
		if ( ! defined( 'ABSPATH' ) ) {
			return null;
		}
		$path = ABSPATH . 'robots.txt';
		if ( is_link( $path ) ) {
			return null;
		}
		if ( is_file( $path ) ) {
			$size = filesize( $path );
			if ( false === $size || $size > 65536 ) {
				return null;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded local robots.txt read. The check does not write a file.
			$text = file_get_contents( $path );
			return is_string( $text ) ? $text : null;
		}
		$public = get_option( 'blog_public', null );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Local site address path only, used to copy the virtual robots.txt prefix.
		$site   = parse_url( (string) site_url() );
		$prefix = is_array( $site ) && isset( $site['path'] ) && is_string( $site['path'] ) ? $site['path'] : '';
		$body   = "User-agent: *\nDisallow: {$prefix}/wp-admin/\nAllow: {$prefix}/wp-admin/admin-ajax.php\n";
		if ( '0' === $public || 0 === $public ) {
			$body .= "Disallow: {$prefix}/\n";
		}
		$filtered = apply_filters( 'robots_txt', $body, $public ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Read the core robots.txt filter. Do not replace it.
		return is_string( $filtered ) && strlen( $filtered ) <= 65536 ? $filtered : null;
	}

	/** @return array<int, array{agents: array<int, string>, root: bool}> */
	private static function groups( string $body ): array {
		$groups  = array();
		$index   = -1;
		$sawRule = false;
		$lines   = preg_split( "/\r\n|\n|\r/", $body );
		if ( false === $lines ) {
			return array();
		}
		foreach ( $lines as $line ) {
			$clean = preg_replace( '/\s+#.*$/', '', trim( $line ) );
			$clean = is_string( $clean ) ? trim( $clean ) : '';
			if ( '' === $clean || str_starts_with( $clean, '#' ) ) {
				continue;
			}
			if ( 1 === preg_match( '/^user-agent\s*:\s*(.+)$/i', $clean, $agent ) ) {
				if ( $index < 0 || $sawRule ) {
					$groups[] = array(
						'agents' => array(),
						'root'   => false,
					);
					$index    = count( $groups ) - 1;
					$sawRule  = false;
				}
				$groups[ $index ]['agents'][] = strtolower( trim( $agent[1] ) );
				continue;
			}
			if ( $index < 0 || 1 !== preg_match( '/^disallow\s*:\s*(.*)$/i', $clean, $rule ) ) {
				if ( $index >= 0 && 1 === preg_match( '/^(allow|crawl-delay)\s*:/i', $clean ) ) {
					$sawRule = true;
				}
				continue;
			}
			$sawRule = true;
			if ( '/' === trim( $rule[1] ) ) {
				$groups[ $index ]['root'] = true;
			}
		}
		return $groups;
	}

	/** @param array<int, array{agents: array<int, string>, root: bool}> $groups */
	private static function blocked( array $groups, string $crawler ): bool {
		$specific = null;
		$star     = null;
		foreach ( $groups as $group ) {
			if ( in_array( $crawler, $group['agents'], true ) ) {
				$specific = $group;
			}
			if ( in_array( '*', $group['agents'], true ) ) {
				$star = $group;
			}
		}
		if ( null !== $specific ) {
			return $specific['root'];
		}
		return null !== $star && $star['root'];
	}
}
