<?php   
header("Content-type: image/png");
$im = imagecreatefrompng("1.png");
imagecolortransparent ( $im,imagecolorallocate($im, 255, 255, 255));
imagepng($im);
imagedestroy($im);
$QUERY_STRING = $_SERVER['QUERY_STRING'];
$HTTP_REFERER = $_SERVER['HTTP_REFERER'];
$HTTP_USER_AGENT = $_SERVER['HTTP_USER_AGENT'];
if ($QUERY_STRING == '') { $QUERY_STRING = '-'; }
if ($HTTP_REFERER == '') { $HTTP_REFERER = '-'; }
if ($HTTP_USER_AGENT == '') { $HTTP_USER_AGENT = '-'; }
//Write Log
    $filename = 'webbug.log';
    $fp = fopen($filename, "a");
    $string = $_SERVER['REMOTE_ADDR'].' '
        .date("[d/M/Y:G:i:s O]").' '      
        .'"'.$HTTP_REFERER.'" '
	.'"'.$QUERY_STRING.'" '
	.'"'.$HTTP_USER_AGENT.'"'."\n";
    $write = fputs($fp, $string);
    fclose($fp);
//end Write Log
?>
