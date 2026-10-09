<?php
namespace AmazingPlugins\Security\Tests\Unit\Rules;
use AmazingPlugins\Security\Rules\RuleCatalog;
use PHPUnit\Framework\TestCase;
final class CatalogTest extends TestCase {
 private string $root;
 protected function setUp():void{
  $this->root=sys_get_temp_dir().'/amsec-rules-'.bin2hex(random_bytes(6));mkdir($this->root,0700);mkdir($this->root.'/assets');
  foreach(RuleCatalog::descriptors() as $pack){foreach($pack['files'] as $path){$dir=dirname($this->root.'/'.$path);if(!is_dir($dir)){mkdir($dir,0700,true);}copy(dirname(__DIR__,3).'/'.$path,$this->root.'/'.$path);}}
  file_put_contents($this->root.'/assets/rule-manifest.json',json_encode((new RuleCatalog($this->root))->buildManifest('2026-09-30')));
 }
 protected function tearDown():void{$it=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->root,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);foreach($it as $f){if($f->isDir()&&!$f->isLink()){rmdir($f->getPathname());}else{unlink($f->getPathname());}}rmdir($this->root);}
 private function change(callable $f):void{$p=$this->root.'/assets/rule-manifest.json';$m=json_decode(file_get_contents($p),true);$f($m);file_put_contents($p,json_encode($m));}
 public function test_current_and_overdue_are_advisory_metadata_status():void{$s=(new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC'));self::assertSame(['recent','recent','recent'],array_column($s,'status'));self::assertSame([39,5,6],array_values(array_map(static fn($p)=>count($p['ids']),$s)));$boundary=strtotime('2026-09-30 UTC');self::assertSame('recent',(new RuleCatalog($this->root))->status($boundary+90*86400-1)['files']['status']);self::assertSame('overdue',(new RuleCatalog($this->root))->status($boundary+90*86400)['files']['status']);$s=(new RuleCatalog($this->root))->status(strtotime('2026-12-30 UTC'));self::assertSame(['overdue','overdue','overdue'],array_column($s,'status'));}
 public function test_future_invalid_date_and_manifest_version_id_mismatch_are_unknown():void{
  foreach(['future','invalid','nul','version','ids','hash'] as $case){file_put_contents($this->root.'/assets/rule-manifest.json',json_encode((new RuleCatalog($this->root))->buildManifest('2026-09-30')));$this->change(static function(&$m)use($case){$p=&$m['packs']['files'];if($case==='future'){$p['reviewed_at']='2027-01-01';}elseif($case==='invalid'){$p['reviewed_at']='2026-02-30';}elseif($case==='nul'){$p['reviewed_at']="2026-09-30\0";}elseif($case==='version'){$p['version']='bad';}elseif($case==='ids'){$p['ids']=[];}else{$p['sha256']['src/FileScan/RuleMatcher.php']=str_repeat('0',64);}});self::assertSame('unknown',(new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC'))['files']['status']);}
 }
 public function test_modified_missing_oversized_and_symlink_source_are_unknown():void{
  $p=$this->root.'/src/FileScan/RuleMatcher.php';$original=file_get_contents($p);foreach(['modified','missing','large','link'] as $case){if(file_exists($p)||is_link($p)){unlink($p);}if($case==='modified'){file_put_contents($p,$original.' ');}elseif($case==='large'){file_put_contents($p,str_repeat('x',262145));}elseif($case==='link'){symlink($this->root.'/src/FileScan/BundledRulePack.php',$p);}self::assertSame('unknown',(new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC'))['files']['status']);}
 }
 public function test_missing_and_oversized_manifest_are_unknown():void{$p=$this->root.'/assets/rule-manifest.json';unlink($p);self::assertSame(['unknown','unknown','unknown'],array_column((new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC')),'status'));file_put_contents($p,str_repeat('x',32769));self::assertSame(['unknown','unknown','unknown'],array_column((new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC')),'status'));}
 public function test_invalid_or_symlink_manifest_and_extra_paths_are_refused():void{
  $p=$this->root.'/assets/rule-manifest.json';$m=json_decode(file_get_contents($p),true);$m['packs']['files']['sha256']['/etc/passwd']=str_repeat('0',64);file_put_contents($p,json_encode($m));self::assertSame('unknown',(new RuleCatalog($this->root))->status(strtotime('2026-09-30 UTC'))['files']['status']);file_put_contents($p,'invalid');self::assertSame(['unknown','unknown','unknown'],array_column((new RuleCatalog($this->root))->status(time()),'status'));unlink($p);symlink($this->root.'/src/FileScan/BundledRulePack.php',$p);self::assertSame(['unknown','unknown','unknown'],array_column((new RuleCatalog($this->root))->status(time()),'status'));
 }
}
