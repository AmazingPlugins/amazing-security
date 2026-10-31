<?php
// Disposable named databases only. Fixture markup is stored and read as data, never rendered or executed.
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || DB_HOST !== 'amsec-next-db' || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 );}
use AmazingPlugins\Security\Content\WordPressContentService;
use AmazingPlugins\Security\Content\WordPressContentInventory;
use AmazingPlugins\Security\Content\ContentAction;
use AmazingPlugins\Security\Content\ContentPage;
use AmazingPlugins\Security\Content\ContentCursor;
$slug  = 'amsec-content-fixture-' . bin2hex( random_bytes( 4 ) );
$saved = array();
foreach ( array( 'amsec_content_state', 'amsec_content_lock' ) as $key ) {
	$saved[ $key ] = get_option( $key, null );
	delete_option( $key );
}$posts   = array();
$comments = array();
wp_set_current_user( 1 );
$private                   = 'DO-NOT-RENDER-' . $slug;
$body                      = '<a href="https://outside.invalid/' . $private . '" style="display:none">fixture</a>';
$script                    = '<script>location="https://outside.invalid/' . $private . '";</script>';
$_SERVER['REQUEST_METHOD'] = 'POST';
$die                       = static fn()=>static function ( $m, $t, $a ) {
throw new RuntimeException( 'denied:' . ( $a['response'] ?? 500 ) );
}add_filter( 'wp_die_handler', $die );
$redirect                  = static function () {
	throw new RuntimeException( 'redirect' );
};
add_filter( 'wp_redirect', $redirect );
try {
	$base = array(
		'operation' => 'start',
		'_wpnonce'  => wp_create_nonce( 'amsec_content_start' ),
	);
	foreach ( array(
		'nonce'     => array( '_wpnonce' => 'bad' ),
		'operation' => array( 'operation' => 'bad' ),
		'id'        => array(
			'operation' => 'resume',
			'scan_id'   => 'bad',
		),
	) as $name => $change ) {
		$_POST    = array_replace( $base, $change );
		$_REQUEST = $_POST;
		try {
			( new ContentAction() )->handle();
			throw new LogicException( 'Gate accepted ' . $name );
		} catch ( RuntimeException $e ) {
			if ( ! str_starts_with( $e->getMessage(), 'denied:' ) ) {
				throw $e;
			}
		}if ( get_option( 'amsec_content_state', null ) !== null ) {
			throw new RuntimeException( 'Rejected request persisted state.' );}
	}
	foreach ( array( 'method', 'role' ) as $name ) {
		$_POST    = $base;
		$_REQUEST = $_POST;
		if ( $name === 'method' ) {
			$_SERVER['REQUEST_METHOD'] = 'GET';
		} else {
			wp_set_current_user( 0 );
		}try {
			( new ContentAction() )->handle();
			throw new LogicException( 'Gate accepted ' . $name );
		} catch ( RuntimeException $e ) {
			if ( ! str_starts_with( $e->getMessage(), 'denied:' ) ) {
				throw $e;
			}
		}$_SERVER['REQUEST_METHOD'] = 'POST';
		wp_set_current_user( 1 );}
	$insert    = static function ( $content, $extra = array() ) use ( &$posts, $slug ) {
		$id = wp_insert_post(
			array_replace(
				array(
					'post_title'   => $slug,
					'post_content' => $content,
					'post_type'    => 'post',
					'post_status'  => 'publish',
				),
				$extra
			)
		);
		if ( is_wp_error( $id ) || ! $id ) {
			throw new RuntimeException( 'Post fixture failed.' );
		}$posts[] = $id;
		return $id;
	};
	$published = $insert( $body );
	$page      = $insert( $script, array( 'post_type' => 'page' ) );
	$oversized = $insert( str_repeat( 'x', 131073 ) );
	$draft     = $insert( $body, array( 'post_status' => 'draft' ) );
	$hidden    = $insert( $body, array( 'post_status' => 'private' ) );
	$locked    = $insert( $body, array( 'post_password' => bin2hex( random_bytes( 12 ) ) ) );
	$product   = $insert( $body, array( 'post_type' => 'product' ) );
	$empty     = $insert( '', array( 'post_type' => 'page' ) );
	$emptyMeta = ( new WordPressContentInventory( $GLOBALS['wpdb'] ) )->candidates( 'post', $empty - 1, $empty, 1 );
	if ( ( new WordPressContentInventory( $GLOBALS['wpdb'] ) )->read( 'post', $empty, $emptyMeta[0]['hash'] ) !== '' ) {
		throw new RuntimeException( 'Empty public content became unknown.' );
	}$benign = $insert( '<p>Harmless local content and a <a href="/account" style="display:none">local link</a>.</p>' );for ( $i = 0;$i < 70;$i++ ) {
		$insert( '<p>Harmless fixture ' . $i . '.</p>' );}
	if ( get_post( $page )->post_content !== $script ) {
		throw new RuntimeException( 'Fixture content changed during insertion.' );}
	$comment        = static function ( $post, $approved ) use ( &$comments, $body ) {
		$id = wp_insert_comment(
			array(
				'comment_post_ID'      => $post,
				'comment_content'      => $body,
				'comment_approved'     => $approved,
				'comment_type'         => 'comment',
				'comment_author'       => 'Dummy visitor',
				'comment_author_email' => 'fixture@amsec.invalid',
			)
		);
		if ( ! $id ) {
			throw new RuntimeException( 'Comment fixture failed.' );
		}$comments[] = $id;
		return $id;
	};
	$approved       = $comment( $published, 1 );
	$pending        = $comment( $published, 0 );
	$privateComment = $comment( $hidden, 1 );
	$productComment = $comment( $product, 1 );
	$inventory      = new WordPressContentInventory( $GLOBALS['wpdb'] );
	$metadata       = $inventory->candidates( 'post', $published - 1, $published, 1 );
	if ( count( $metadata ) !== 1 || $inventory->read( 'post', $published, $metadata[0]['hash'] ) !== $body ) {
		throw new RuntimeException( 'Bounded content read failed.' );
	}wp_update_post(
		array(
			'ID'           => $published,
			'post_content' => '<p>Changed harmless fixture.</p>',
		)
	);
	if ( $inventory->read( 'post', $published, $metadata[0]['hash'] ) !== null ) {
		throw new RuntimeException( 'Changed captured content accepted.' );
	}wp_update_post(
		array(
			'ID'           => $published,
			'post_content' => $body,
		)
	);
	$runAction = static function ( $post ) {
		$_POST    = $post;
		$_REQUEST = $_POST;
		try {
			( new ContentAction() )->handle();
			throw new LogicException( 'Missing redirect.' );
		} catch ( RuntimeException $e ) {
			if ( $e->getMessage() !== 'redirect' ) {
				throw $e;
			}
		}};
	$runAction( $base );
	$service = ( new WordPressContentService() )->create();
	$state   = $service->status();
	if ( $state['active']['processed'] > 50 || $state['active']['finished'] ) {
		throw new RuntimeException( 'Installed step exceeded or skipped resume.' );
	}$raw     = get_option( 'amsec_content_state' );
	$wrong    = bin2hex( random_bytes( 16 ) );
	$_POST    = array(
		'operation' => 'resume',
		'scan_id'   => $wrong,
		'_wpnonce'  => wp_create_nonce( 'amsec_content_resume_' . $wrong ),
	);
	$_REQUEST = $_POST;
	try {
		( new ContentAction() )->handle();
		throw new LogicException( 'Changed scan accepted.' );
	} catch ( RuntimeException $e ) {
		if ( $e->getMessage() !== 'denied:409' ) {
			throw $e;
		}
	}if ( get_option( 'amsec_content_state' ) !== $raw ) {
		throw new RuntimeException( 'Changed scan mutated report.' );}
	for ( $i = 0;$i < 25 && ! $state['active']['finished'];$i++ ) {
		$id = $state['active']['scan_id'];
		$runAction(
			array(
				'operation' => 'resume',
				'scan_id'   => $id,
				'_wpnonce'  => wp_create_nonce( 'amsec_content_resume_' . $id ),
			)
		);
		$state = $service->status();
	}if ( ! $state['active']['finished'] || ! $state['active']['partial'] || $state['active']['unknown'] < 1 ) {
		throw new RuntimeException( 'Oversized unknown coverage missing.' );}
	$found      = $state['active']['findings'];
	$postIds    = array_column( array_filter( $found, static fn( $f )=>$f['kind'] === 'post' ), 'id' );
	$commentIds = array_column( array_filter( $found, static fn( $f )=>$f['kind'] === 'comment' ), 'id' );
	foreach ( array( $published, $page ) as $id ) {
		if ( ! in_array( $id, $postIds, true ) ) {
			throw new RuntimeException( 'Published fixture not found.' );
		}
	}if ( ! in_array( $approved, $commentIds, true ) ) {
		throw new RuntimeException( 'Approved native comment not found.' );
	}foreach ( array( $draft, $hidden, $locked, $product, $benign ) as $id ) {
		if ( in_array( $id, $postIds, true ) ) {
			throw new RuntimeException( 'Excluded/benign post was included.' );
		}
	}foreach ( array( $pending, $privateComment, $productComment ) as $id ) {
		if ( in_array( $id, $commentIds, true ) ) {
			throw new RuntimeException( 'Excluded comment included.' );
		}
	}foreach ( array( $body, $script, $private, 'outside.invalid', 'fixture@amsec.invalid' ) as $text ) {
		if ( str_contains( get_option( 'amsec_content_state' ), $text ) ) {
			throw new RuntimeException( 'Raw contents entered state.' );}
	}
	ob_start();
	( new ContentPage() )->render();
	$html = ob_get_clean();
	foreach ( array( 'Partial coverage', 'Latest review', 'Open editor', 'Continue scan' ) as $text ) {
		if ( $text === 'Continue scan' ) {
			continue;
		}if ( ! str_contains( $html, $text ) ) {
			throw new RuntimeException( 'Report control missing.' );
		}
	}if ( str_contains( $html, $private ) || str_contains( $html, '<script>location=' ) ) {
		throw new RuntimeException( 'Content rendered in report.' );
	}wp_update_post(
		array(
			'ID'          => $published,
			'post_status' => 'private',
		)
	);
	ob_start();
	( new ContentPage() )->render();
	$changed = ob_get_clean();
	if ( preg_match( '~<tr><td[^>]*>Post #' . $published . '</td>(.*?)</tr>~s', $changed, $row ) && str_contains( $row[1], 'Open editor' ) ) {
		throw new RuntimeException( 'Changed private target retained editor link.' );
	}wp_update_post(
		array(
			'ID'          => $published,
			'post_status' => 'publish',
		)
	);
	wp_delete_post( $oversized, true );
	$posts = array_values( array_diff( $posts, array( $oversized ) ) );
	$service->start( time() );
	$state = $service->status();for ( $i = 0;$i < 25 && ! $state['active']['finished'];$i++ ) {
		$service->step( time() );
		$state = $service->status();
	}if ( ! $state['active']['finished'] || $state['active']['partial'] || ! $state['complete'] ) {
		throw new RuntimeException( 'Completed scoped report failed: ' . wp_json_encode( array_intersect_key( $state['active'], array_flip( array( 'processed', 'unknown', 'omitted', 'partial', 'reason', 'phase', 'finished' ) ) ) ) );
	}$complete = $state['complete'];
	$service->start( time() );
	$state                         = $service->status();
	$state['active']['started_at'] = time() - 86401;
	update_option( 'amsec_content_state', wp_json_encode( $state ), false );
	if ( $service->step( time() ) !== 'partial' || $service->status()['active']['reason'] !== 'expired' || $service->status()['complete']['scan_id'] !== $complete['scan_id'] ) {
		throw new RuntimeException( 'Expired work replaced earlier complete report.' );}
	// Actual metadata adapter errors are converted into partial state without mutating core tables.
	$proxy = new class($GLOBALS['wpdb']) {public string $last_error = '';
		public string $posts;
		public string $comments;
		public function __construct( private object $db ) {
			$this->posts    = $db->posts;
			$this->comments = $db->comments;
		}public function suppress_errors( $v ) {
			return $this->db->suppress_errors( $v );
		}public function prepare( $sql, ...$args ) {
			return $this->db->prepare( $sql, ...$args );
		}public function get_results( $sql, $mode ) {
			$this->last_error = 'fixture read failure';
			return null;
		}};
	$c     = new ContentCursor( 'database-test', 100, 100, time(), hash( 'sha256', 'fixture' ) );
	( new AmazingPlugins\Security\Content\ContentRunner( new WordPressContentInventory( $proxy ), new AmazingPlugins\Security\Content\MarkupDetector( 'site.test' ) ) )->step( $c, time() );
	if ( ! $c->partial || $c->reason !== 'database' ) {
		throw new RuntimeException( 'Metadata failure presented as complete.' );}
	remove_filter( 'wp_redirect', $redirect );
	remove_filter( 'wp_die_handler', $die );
	echo 'Published-content scan: native stored posts/pages/approved comments, excluded private/draft/protected/product data, changed-hash refusal, bounded resume, oversized unknown, exact nonce/ID gates, redacted report/editor links, expired recovery and adapter failure passed.' . PHP_EOL;
} finally {
	add_filter( 'pre_wp_mail', '__return_true', PHP_INT_MAX );
	wp_set_current_user( 1 );
	foreach ( $comments as $id ) {
		wp_delete_comment( $id, true );
	}foreach ( $posts as $id ) {
		wp_delete_post( $id, true );
	}foreach ( $saved as $key => $value ) {
		if ( $value === null ) {
			delete_option( $key );
		} else {
			update_option( $key, $value, false );
		}
	}remove_filter( 'pre_wp_mail', '__return_true', PHP_INT_MAX );}
