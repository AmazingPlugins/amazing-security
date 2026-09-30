<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityRenderer {
	public function render( array $rows, int $page, string $event ): string {
		$html = '<div class="wrap amazing-security-admin"><h1>Security activity</h1><p>Local history is best effort. Events can be missing, and someone with database access can change them. Retention is up to 30 days or 10,000 events; failed-login records have a separate budget.</p><form method="get"><input type="hidden" name="page" value="amsec-activity"><label for="amsec-event">Event type</label> <select id="amsec-event" name="event"><option value="">All events</option>';
		foreach ( ActivityEvent::TYPES as $type ) {
			$html .= '<option value="' . esc_attr( $type ) . '"' . ( $type === $event ? ' selected' : '' ) . '>' . esc_html( str_replace( '_', ' ', $type ) ) . '</option>';
		}
		$html .= '</select> <button class="button">Filter</button></form><div style="overflow-x:auto"><table class="widefat striped"><caption class="screen-reader-text">Recorded security events</caption><thead><tr><th scope="col">Time UTC</th><th scope="col">Event</th><th scope="col">Actor ID</th><th scope="col">User ID</th><th scope="col">Target</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$html .= '<tr><td>' . esc_html( gmdate( 'Y-m-d H:i:s', (int) $row['created_at'] ) ) . '</td><td>' . esc_html( str_replace( '_', ' ', $row['event'] ) ) . '</td><td>' . esc_html( (string) (int) $row['actor_id'] ) . '</td><td>' . esc_html( (string) (int) $row['user_id'] ) . '</td><td>' . esc_html( $row['target'] ) . '</td></tr>';
		}
		if ( array() === $rows ) {
			$html .= '<tr><td colspan="5">No recorded events for this selection. This does not establish that no activity occurred.</td></tr>';
		}
		$html .= '</tbody></table></div><p>Page ' . esc_html( (string) $page ) . '. Actor 0 means no authenticated actor was available.</p>';
		foreach ( array(
			'Previous' => $page - 1,
			'Next'     => $page + 1,
		) as $label => $next ) {
			if ( $next >= 1 && $next <= 200 && ( 'Next' !== $label || 50 === count( $rows ) ) ) {
				$html .= '<a class="button" href="' . esc_url(
					add_query_arg(
						array(
							'page'          => 'amsec-activity',
							'activity_page' => $next,
							'event'         => $event,
						),
						admin_url( 'admin.php' )
					)
				) . '">' . esc_html( $label ) . '</a> ';
			}
		}
		return $html . '</div>';
	}
}
