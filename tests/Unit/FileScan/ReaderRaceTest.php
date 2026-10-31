<?php
namespace AmazingPlugins\Security\FileScan {
 function fread($handle,$length){$bytes=\fread($handle,$length);$callback=$GLOBALS['amsec_reader_race']??null;if(is_callable($callback)){unset($GLOBALS['amsec_reader_race']);$callback($handle);}return $bytes;}
}
namespace AmazingPlugins\Security\Tests\Unit\FileScan {
 use AmazingPlugins\Security\FileScan\BoundedContentReader;
 use AmazingPlugins\Security\Integrity\IntegrityBudget;
 use PHPUnit\Framework\TestCase;
 final class ReaderRaceTest extends TestCase {
  public function test_external_mid_read_mutation_is_refused_with_fresh_stat(): void {
   if(!function_exists('exec')){$this->markTestSkipped('PHP subprocess unavailable.');}
   $root=realpath(sys_get_temp_dir()).'/amsec-reader-race-'.bin2hex(random_bytes(4));mkdir($root,0700);$path=$root.'/fixture.php';file_put_contents($path,str_repeat('x',1048576));
   $GLOBALS['amsec_reader_race']=static function()use($path){$command=escapeshellarg(PHP_BINARY).' -r '.escapeshellarg('file_put_contents($argv[1],str_repeat("y",1048576));touch($argv[1],time()+10);').' '.escapeshellarg($path);exec($command,$output,$code);if($code!==0){throw new \RuntimeException('Fixture subprocess failed.');}};
   try{self::assertSame('unsafe',(new BoundedContentReader())->read($root,'fixture.php',new IntegrityBudget())->state);}finally{unset($GLOBALS['amsec_reader_race']);unlink($path);rmdir($root);}
  }
 }
}
