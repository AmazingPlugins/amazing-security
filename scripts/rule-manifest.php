<?php
// Explicit development command; never invoked by plugin requests.
declare(strict_types=1);
if(!defined('ABSPATH'))define('ABSPATH',sys_get_temp_dir().'/');
foreach(['src/Content/MarkupDetector.php','src/FileScan/BundledRulePack.php','src/Firewall/BundledRequestRules.php','src/Rules/RuleCatalog.php'] as $file){require dirname(__DIR__).'/'.$file;}
use AmazingPlugins\Security\Rules\RuleCatalog;
$root=dirname(__DIR__);$catalog=new RuleCatalog($root);$path=$root.'/assets/rule-manifest.json';
if($argc===3&&$argv[1]==='--write'&&str_starts_with($argv[2],'--review-date=')){
 $manifest=$catalog->buildManifest(substr($argv[2],14));if(file_put_contents($path,json_encode($manifest,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n")===false){throw new RuntimeException('Manifest write failed.');}echo "Wrote bundled review metadata; review and commit it with release evidence.\n";exit(0);
}
if($argc!==2||$argv[1]!=='--check'){fwrite(STDERR,"Usage: php scripts/rule-manifest.php --check | --write --review-date=YYYY-MM-DD\n");exit(2);}
$status=$catalog->status(time());foreach($status as $id=>$p){if($p['status']==='unknown'){fwrite(STDERR,"Bundled manifest/source mismatch or invalid date: $id\n");exit(1);}}
echo "Bundled rule versions, IDs and source hashes match. Metadata age remains an advisory.\n";
