<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class FirewallStatusRenderer {
	public function render( array $summary ): string {
		$total = 0;
		foreach ( $summary as $item ) {
			$total += max( 0, (int) ( $item['count'] ?? 0 ) );
		}
		return '<section class="amsec-firewall-status" aria-labelledby="amsec-firewall-title"><h2 id="amsec-firewall-title">REST request watch</h2><p><strong>Observe only.</strong> Checks public REST query values and five levels of the request body for a path step-up, a SQL union, a script tag, a PHP stream wrapper, a null byte, or an onload or onerror attribute. A sixth layer of encoding is checked too. It does not store those values or block requests. A seventh layer of encoding, and fields nested further than five levels, are not matched. Counts may miss matches during simultaneous requests and stop at 9,999 per rule.</p><p>' . esc_html( (string) $total ) . ' suspect matches recorded on this site. Rule pack ' . esc_html( ( new BundledRequestRules() )->version() ) . '.</p></section>';
	}
}
