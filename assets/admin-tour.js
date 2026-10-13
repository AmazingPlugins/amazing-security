( function ( $ ) {
	var d = window.amsecTour;
	var steps = d.steps.filter( function ( s ) {
		return $( s.target ).filter( ':visible' ).length;
	} );
	var hasMenu = steps.some( function ( s ) {
		return $( s.target ).closest( '#adminmenu' ).length;
	} );
	// Phones hide the side menu behind a toggle, so one step points at the toggle instead.
	if ( ! hasMenu && $( d.phone.target ).filter( ':visible' ).length ) {
		steps.unshift( d.phone );
	}
	var i = 0;
	var $dim = $( '<div class="amsec-tour-dim"></div>' );

	function clear() {
		$( '.amsec-tour-target' ).removeClass( 'amsec-tour-target' );
	}

	function finish() {
		clear();
		$dim.remove();
		$.post( window.ajaxurl, { action: 'dismiss-wp-pointer', pointer: d.pointer } );
	}

	function show() {
		var s = steps[ i ];
		var last = i === steps.length - 1;
		var $el = $( s.target ).filter( ':visible' ).first();
		clear();
		$el.addClass( 'amsec-tour-target' );
		if ( ! $el.closest( '#adminmenu, #wpadminbar' ).length ) {
			$el[ 0 ].scrollIntoView( { block: 'center' } );
		}
		$el.pointer( {
			content: $( '<div>' ).append( $( '<h3>' ).text( s.title ), $( '<p>' ).text( s.text ) ).html(),
			position: s.edge ? { edge: s.edge, align: 'left' } : { edge: 'left', align: 'center' },
			close: function () {},
			buttons: function ( e, t ) {
				var $skip = $( '<a href="#" class="button-link">' ).text( d.skip ).css( { float: 'left', 'line-height': '2.4' } );
				var $next = $( '<a href="#" class="button button-primary">' ).text( last ? d.done : d.next ).css( 'float', 'right' );
				$skip.on( 'click', function ( ev ) {
					ev.preventDefault();
					t.element.pointer( 'close' );
					finish();
				} );
				$next.on( 'click', function ( ev ) {
					ev.preventDefault();
					t.element.pointer( 'close' );
					if ( last ) {
						finish();
					} else {
						i++;
						show();
					}
				} );
				return $( '<span>' ).append( $skip, $next );
			},
		} ).pointer( 'open' );
	}

	if ( steps.length ) {
		$( 'body' ).append( $dim );
		show();
	}
}( jQuery ) );
