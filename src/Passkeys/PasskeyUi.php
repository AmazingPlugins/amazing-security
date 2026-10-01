<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyUi {
	public function __construct( private readonly object $db ) {}
	public function adminAssets( string $hook ): void {
		if ( 'profile.php' === $hook ) {
			$this->assets(); }
	}
	public function loginAssets(): void {
		if ( is_ssl() && null !== ( new PasskeyRuntime( $this->db ) )->configuration() ) {
			$this->assets(); }
	}
	public function assets(): void {
		wp_enqueue_script( 'amsec-passkeys', plugins_url( 'assets/passkeys.js', AMAZING_SECURITY_FILE ), array(), '0.1.0', true );
		wp_enqueue_style( 'amsec-passkeys', plugins_url( 'assets/passkeys.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
		wp_localize_script(
			'amsec-passkeys',
			'amsecPasskeys',
			array(
				'endpoint'    => admin_url( 'admin-post.php', 'https' ),
				'working'     => __( 'Follow the instructions from your device…', 'amazing-security' ),
				'failed'      => __( 'The passkey request could not be completed. Check your details and try again. You can still use your password.', 'amazing-security' ),
				'unsupported' => __( 'Passkeys need HTTPS and a supported browser. You can still use your password.', 'amazing-security' ),
				'approval'    => __( 'Enter your current password and confirm the change first.', 'amazing-security' ),
				'saved'       => __( 'Saved. Reloading your passkeys…', 'amazing-security' ),
			)
		);
	}
	public function profile( \WP_User $user ): void {
		if ( get_current_user_id() !== $user->ID || ! current_user_can( 'read' ) ) {
			return; }
		$this->assets();
		$runtime    = new PasskeyRuntime( $this->db );
		$enabled    = is_ssl() && null !== $runtime->configuration();
		$records    = ( new PasskeyRepository( $this->db ) )->ownCredentials( $user->ID, time() );
		$manageable = is_ssl() && null !== $runtime->configuration( false ) && null !== $records;
		?>
		<section id="amsec-passkeys" class="amsec-passkeys" aria-labelledby="amsec-passkeys-title">
		<h2 id="amsec-passkeys-title"><?php esc_html_e( 'Your passkeys', 'amazing-security' ); ?></h2>
		<p><?php esc_html_e( 'Sign in with your device’s screen lock or security key. Your existing verification-code and account policies still apply.', 'amazing-security' ); ?></p>
		<p class="description"><?php esc_html_e( 'This preview supports discoverable passkeys with device verification and ES256. Your device or passkey provider manages the private key; this site stores its public key. Some authenticators are not supported.', 'amazing-security' ); ?></p>
		<p class="description"><?php esc_html_e( 'Your username and display name are sent to your device so it can label this passkey. That device decides whether the passkey syncs to your other devices.', 'amazing-security' ); ?></p>
		<?php
		if ( ! $enabled ) :
			?>
			<p class="amsec-passkey-note"><?php esc_html_e( 'Adding passkeys is unavailable. An administrator must enable passkeys, and this page must use HTTPS. Password sign-in remains available.', 'amazing-security' ); ?></p><?php endif; ?>
		<ul class="amsec-passkey-list">
		<?php
		foreach ( $records ?? array() as $item ) :
			$record = $item['record'];
			?>
		<li><div><strong><?php echo esc_html( $record['label'] ); ?></strong><span class="description"><?php echo esc_html( sprintf( /* translators: 1: date added, 2: last use date. */ __( 'Added %1$s · Last used %2$s', 'amazing-security' ), wp_date( 'M j, Y', $record['created_at'] ), $record['last_used_at'] ? wp_date( 'M j, Y', $record['last_used_at'] ) : __( 'Never', 'amazing-security' ) ) ); ?></span></div><button type="button" class="button amsec-passkey-remove" data-credential="<?php echo esc_attr( $item['id'] ); ?>" <?php disabled( ! $manageable ); ?>><?php echo esc_html( sprintf( /* translators: %s: user chosen passkey label. */ __( 'Remove %s', 'amazing-security' ), $record['label'] ) ); ?></button></li>
		<?php endforeach; ?>
		<?php
		if ( null === $records ) :
			?>
			<li><?php esc_html_e( 'Passkeys could not be loaded. Ask an administrator to check storage.', 'amazing-security' ); ?></li>
			<?php
elseif ( array() === $records ) :
	?>
			<li><?php esc_html_e( 'No passkeys added yet.', 'amazing-security' ); ?></li><?php endif; ?>
		</ul>
		<input type="hidden" id="amsec-passkey-nonce" value="<?php echo esc_attr( wp_create_nonce( 'amsec_passkey_own_' . $user->ID ) ); ?>">
		<div class="amsec-passkey-fields">
		<p><label for="amsec-passkey-label"><?php esc_html_e( 'Passkey name', 'amazing-security' ); ?></label><input id="amsec-passkey-label" type="text" maxlength="80" autocomplete="off" placeholder="<?php esc_attr_e( 'For example, personal laptop', 'amazing-security' ); ?>"></p>
		<p><label for="amsec-passkey-password"><?php esc_html_e( 'Current password', 'amazing-security' ); ?></label><input id="amsec-passkey-password" type="password" autocomplete="current-password" maxlength="1024"></p>
		<p><label for="amsec-passkey-factor"><?php esc_html_e( 'Verification or recovery code, if enrolled', 'amazing-security' ); ?></label><input id="amsec-passkey-factor" type="text" autocomplete="one-time-code" maxlength="128"></p>
		</div>
		<p><label><input id="amsec-passkey-confirm" type="checkbox"> <?php esc_html_e( 'I approve adding or removing a passkey on my account.', 'amazing-security' ); ?></label></p>
		<button type="button" class="button button-primary" id="amsec-passkey-add" <?php disabled( ! $enabled || null === $records || count( $records ) >= 5 ); ?>><?php esc_html_e( 'Add a passkey', 'amazing-security' ); ?></button>
		<p class="amsec-passkey-status" role="status" aria-live="polite"></p>
		<p class="description"><?php esc_html_e( 'Keep your password and recovery codes somewhere safe. You can add up to five passkeys. If a device is lost, remove its passkey here; if you cannot sign in, ask your site administrator or host for recovery. Changing the site domain requires new passkeys.', 'amazing-security' ); ?></p>
		<noscript><p><?php esc_html_e( 'Passkey controls require JavaScript.', 'amazing-security' ); ?></p></noscript>
		</section>
		<?php
	}
	public function login(): void {
		if ( get_current_user_id() || ! is_ssl() || null === ( new PasskeyRuntime( $this->db ) )->configuration() ) {
			return; }
		$this->assets();
		?>
		<div class="amsec-passkey-login"><button type="button" class="button button-secondary" id="amsec-passkey-signin"><?php esc_html_e( 'Sign in with a passkey', 'amazing-security' ); ?></button><p class="description"><?php esc_html_e( 'Sign in with a passkey. You only need a verification code when you sign in with your password.', 'amazing-security' ); ?></p><p class="amsec-passkey-status" role="status" aria-live="polite"></p></div>
		<?php
	}
}
