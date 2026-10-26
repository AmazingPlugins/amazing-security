<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Allowed HTML for admin renderer output: post HTML plus the form controls the screens use. */
final class AdminHtml {
	/** @var array<string, array<string, bool>>|null */
	private static ?array $allowed = null;

	/** @return array<string, array<string, bool>> */
	public static function allowed(): array {
		if ( null !== self::$allowed ) {
			return self::$allowed;
		}
		$control = array_fill_keys( array( 'type', 'name', 'value', 'checked', 'selected', 'disabled', 'readonly', 'required', 'multiple', 'placeholder', 'min', 'max', 'step', 'maxlength', 'minlength', 'pattern', 'size', 'rows', 'cols', 'autocomplete', 'inputmode', 'spellcheck', 'form' ), true );
		$tags    = wp_kses_allowed_html( 'post' );
		$extra   = array(
			'form'     => array_fill_keys( array( 'method', 'action', 'enctype', 'novalidate' ), true ),
			'input'    => $control,
			'select'   => $control,
			'option'   => $control,
			'textarea' => $control,
			'button'   => $control,
			'label'    => array( 'for' => true ),
			'fieldset' => array( 'disabled' => true ),
			'legend'   => array(),
			'details'  => array( 'open' => true ),
			'summary'  => array(),
			'time'     => array( 'datetime' => true ),
		);
		foreach ( $extra as $tag => $attributes ) {
			$tags[ $tag ] = array_merge( $tags[ $tag ] ?? array(), $attributes );
		}
		foreach ( $tags as $tag => $attributes ) {
			$tags[ $tag ] = array_merge( is_array( $attributes ) ? $attributes : array(), array_fill_keys( array( 'class', 'id', 'style', 'role', 'tabindex', 'hidden', 'title' ), true ) );
		}
		// Adds aria-* and data-* to every tag, as WordPress does for post HTML.
		self::$allowed = array_map( '_wp_add_global_attributes', $tags );
		return self::$allowed;
	}
}
