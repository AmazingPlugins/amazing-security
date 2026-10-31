<?php
namespace AmazingPlugins\Security\Tests\Unit\Exposure;
use AmazingPlugins\Security\Exposure\ExposureScanner;
use PHPUnit\Framework\TestCase;
final class ScannerTest extends TestCase {
 private string $root;
 protected function setUp():void{$this->root=sys_get_temp_dir().'/amsec-exposure-'.bin2hex(random_bytes(5));mkdir($this->root,0700);}
 protected function tearDown():void{$it=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->root,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);foreach($it as $f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($this->root);}
 public function test_selected_names_and_counterexamples_without_content_reads():void{
  foreach(['debug.log','error_log','export.sql.gz','.env.local','wp-config.php.bak','archive.zip','portrait.jpg','wp-config.php','notes.txt','backup.zip.jpg'] as $name){file_put_contents($this->root.'/'.$name,'INERT-NONSECRET-CONTENT');}$r=(new ExposureScanner())->scan($this->root,'site',1000);self::assertFalse($r['partial']);self::assertCount(6,$r['candidates']);self::assertStringNotContainsString($this->root,json_encode($r));self::assertStringNotContainsString('INERT-NONSECRET-CONTENT',json_encode($r));foreach($r['candidates'] as $c){self::assertSame('INERT-NONSECRET-CONTENT',file_get_contents($this->root.'/'.$c['path']));}
 }
 public function test_symlinks_missing_roots_and_inaccessible_metadata_are_unknown():void{
  file_put_contents($this->root.'/safe.txt','x');symlink($this->root.'/safe.txt',$this->root.'/backup.zip');$r=(new ExposureScanner())->scan($this->root,'site',1000);self::assertTrue($r['partial']);self::assertSame(1,$r['unknown']);self::assertSame([], $r['candidates']);$r=(new ExposureScanner())->scan($this->root.'/missing','uploads',1000);self::assertContains('root_unavailable',$r['reasons']);$stat=static fn($p)=>basename($p)==='safe.txt'?null:lstat($p);$r=(new ExposureScanner(null,$stat))->scan($this->root,'site',1000);self::assertSame(2,$r['unknown']);
 }
 public function test_top_level_scope_and_upload_depth_are_explicit():void{
  $dir=$this->root;for($n=0;$n<5;$n++){$dir.='/nested';mkdir($dir);file_put_contents($dir.'/backup.zip','x');}$r=(new ExposureScanner())->scan($this->root,'site',1000);self::assertCount(0,$r['candidates']);self::assertSame(1,$r['excluded']);$r=(new ExposureScanner())->scan($this->root,'uploads',1000);self::assertCount(3,$r['candidates']);self::assertContains('depth_limit',$r['reasons']);self::assertTrue($r['partial']);
 }
 public function test_candidate_entry_directory_and_work_bounds():void{
  for($n=0;$n<101;$n++){file_put_contents($this->root.'/'.$n.'.zip','x');}$r=(new ExposureScanner())->scan($this->root,'site',1000);self::assertCount(100,$r['candidates']);self::assertContains('candidate_limit',$r['reasons']);foreach(glob($this->root.'/*.zip') as $f){unlink($f);}for($n=0;$n<1501;$n++){file_put_contents($this->root.'/'.$n.'.txt','x');}$r=(new ExposureScanner())->scan($this->root,'site',1000);self::assertSame(1500,$r['entries']);self::assertContains('entry_limit',$r['reasons']);foreach(glob($this->root.'/*.txt') as $f){unlink($f);}for($n=0;$n<51;$n++){mkdir($this->root.'/d'.$n);}$r=(new ExposureScanner())->scan($this->root,'uploads',1000);self::assertSame(50,$r['directories']);self::assertContains('directory_limit',$r['reasons']);$time=0;$clock=static function()use(&$time){return $time++;};$r=(new ExposureScanner($clock))->scan($this->root,'uploads',1000);self::assertContains('work_target',$r['reasons']);
 }
 public function test_changed_file_metadata_is_unknown_not_a_stable_candidate():void{
  file_put_contents($this->root.'/backup.zip','x');$calls=0;$stat=static function($p)use(&$calls){$s=lstat($p);if(basename($p)==='backup.zip'&&++$calls===2){$s['ino']++;}return $s;};$r=(new ExposureScanner(null,$stat))->scan($this->root,'site',1000);self::assertSame(1,$r['unknown']);self::assertSame([],$r['candidates']);
 }
}
