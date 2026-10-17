<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Alerts;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class WordPressAlertNotifier {
	public function create(): AlertNotifier {
		return new AlertNotifier( new AlertPolicy(), $this->delivery() );
	}

	public function delivery(): AlertDelivery {
		return new AlertDelivery(
			new WordPressOptions(),
			static fn( string $to, string $subject, string $message ): bool => wp_mail( $to, $subject, $message ),
			(string) get_option( 'admin_email', '' ),
			admin_url( 'admin.php?page=amazing-security' )
		);
	}
}
