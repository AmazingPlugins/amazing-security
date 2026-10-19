<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** In-page tabs. A click stays on this screen. */
final class ScreenTabs {
	/**
	 * @param array<string, string> $tabs
	 */
	public static function bar( array $tabs ): void {
		echo '<div class="amsec-screen-tabs" role="tablist" data-amsec-tabs>';
		$first = true;
		foreach ( $tabs as $id => $label ) {
			if ( 1 !== preg_match( '/^[a-z0-9-]+$/D', $id ) ) {
				continue;
			}
			echo '<button type="button" role="tab" id="amsec-tab-' . esc_attr( $id ) . '" aria-controls="amsec-panel-' . esc_attr( $id ) . '" data-amsec-tab="' . esc_attr( $id ) . '" aria-selected="' . ( $first ? 'true' : 'false' ) . '" tabindex="' . ( $first ? '0' : '-1' ) . '"' . ( $first ? ' class="is-current"' : '' ) . '>' . esc_html( $label ) . '</button>';
			$first = false;
		}
		echo '</div>';
	}

	public static function panel( string $id, bool $open ): void {
		echo '<div class="amsec-tab-panel" role="tabpanel" id="amsec-panel-' . esc_attr( $id ) . '" aria-labelledby="amsec-tab-' . esc_attr( $id ) . '" tabindex="0" data-amsec-panel="' . esc_attr( $id ) . '"' . ( $open ? '' : ' hidden' ) . '>';
		ob_start();
	}

	/** A screen embedded in a tab keeps one h1 per page: its own title becomes an h2. */
	public static function close(): void {
		$html = (string) ob_get_clean();
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Already-escaped panel markup; only the heading tag name changes.
		echo preg_replace( '~<(/?)h1(?=[\s>])~i', '<$1h2', $html ) ?? $html;
		echo '</div>';
	}
}
