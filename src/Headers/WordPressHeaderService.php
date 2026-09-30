<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

use AmazingPlugins\Security\Integrity\WordPressOptions;
final class WordPressHeaderService {
	public function create(): HeaderService {
		return new HeaderService( new WordPressOptions(), new CurlHeaderClient(), static fn()=>get_option( 'home' ) );}
}
