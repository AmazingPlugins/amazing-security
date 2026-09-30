<?php
// CLI-only reader. Corpus files are data, never included or executed.
if ( PHP_SAPI !== 'cli' || empty( $argv[1] ) || ! is_dir( $argv[1] ) ) { exit( 1 ); }
require dirname( __DIR__, 2 ) . '/vendor/autoload.php';
$m=new AmazingPlugins\Security\FileScan\RuleMatcher(new AmazingPlugins\Security\FileScan\BundledRulePack());
$root=rtrim(realpath($argv[1]), '/');$out=[];$count=0;
foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS)) as $f){
 if($f->isLink() || ! $f->isFile() || !in_array($f->getExtension(),['php','txt'],true))continue;
 if(++$count>20000){throw new RuntimeException('Corpus inventory limit');}
 if($f->getSize()>2097152){$out[]=['path'=>substr($f->getPathname(),strlen($root)+1),'hits'=>[],'excluded'=>'oversized'];continue;}
 $path=substr($f->getPathname(),strlen($root)+1);$bytes=file_get_contents($f->getPathname());
 try{$hits=$m->match($bytes,$path);$out[]=['path'=>$path,'sha256'=>hash('sha256',$bytes),'hits'=>array_column($hits,'ruleId'),'excluded'=>null];}
 catch(RuntimeException $e){$out[]=['path'=>$path,'sha256'=>hash('sha256',$bytes),'hits'=>[],'excluded'=>$e->getMessage()];}
}
echo json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
