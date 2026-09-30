<?php
if(!defined('WP_CLI')||!WP_CLI||DB_HOST!=='amsec-next-db'||!in_array(DB_NAME,['wordpress','wordpress69'],true)){exit(1);}
$form=WPCF7_ContactForm::get_template();$form->set_title('Amazing Security dummy form');$form->save();
$product=new WC_Product_Simple();$product->set_name('Amazing Security dummy product');$product->set_regular_price('5');$productId=$product->save();
$page=wp_insert_post(['post_title'=>'Amazing Security compatibility fixture','post_status'=>'publish','post_type'=>'page','post_content'=>'[contact-form-7 id="'.$form->id().'"][product_page id="'.$productId.'"]']);
if(is_wp_error($page)||!$page){throw new RuntimeException('Frontend fixture failed.');}
update_option('home','http://localhost');update_option('siteurl','http://localhost');
echo (int)$page;
