<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

use AmazingPlugins\Security\Integrity\WordPressOptions;
final class WordPressDirectoryService {
	public function create(): DirectoryService {
		return new DirectoryService( new WordPressOptions(), new WordPressDirectoryClient(), array( new WordPressDirectoryInventory(), 'find' ) );}
}
