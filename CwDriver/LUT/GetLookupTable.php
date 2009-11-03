<?

//table built from URL:
//	http://www.metasploit.com/users/opcode/syscalls.html


function strip_html_tags( $text )
{
    $text = preg_replace(
        array(
            '@<head[^>]*?>.*?</head>@siu',
            '@<style[^>]*?>.*?</style>@siu',
            '@<script[^>]*?.*?</script>@siu',
            '@<object[^>]*?.*?</object>@siu',
            '@<embed[^>]*?.*?</embed>@siu',
            '@<applet[^>]*?.*?</applet>@siu',
            '@<noframes[^>]*?.*?</noframes>@siu',
            '@<noscript[^>]*?.*?</noscript>@siu',
            '@<noembed[^>]*?.*?</noembed>@siu',
            '@</?((address)|(blockquote)|(center)|(del))@iu',
            '@</?((div)|(h[1-9])|(ins)|(isindex)|(p)|(pre))@iu',
            '@</?((dir)|(dl)|(dt)|(dd)|(li)|(menu)|(ol)|(ul))@iu',
            '@</?((table)|(th)|(td)|(caption))@iu',
            '@</?((form)|(button)|(fieldset)|(legend)|(input))@iu',
            '@</?((label)|(select)|(optgroup)|(option)|(textarea))@iu',
            '@</?((frameset)|(frame)|(iframe))@iu',
        ),
        array(' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',"\n\$0", "\n\$0", "\n\$0", "\n\$0", "\n\$0", "\n\$0","\n\$0", "\n\$0",),$text);
        
    return strip_tags($text,"<html><head><body><table><tr><td>");
}

//get contents of html table from URL
$data=file_get_contents("http://www.metasploit.com/users/opcode/syscalls.html");
//strip out all tags but table and simple html
$data=strip_html_tags($data);
//strip out the NTSYSAPI ... (); function declaration details
$start=strpos($data,"NTSYSAPI");
while ($start !== false)
{
	$end=strpos($data,");",$start);
	$data=substr_replace($data,"",$start,$end-($start-1));
	$start=strpos($data,"NTSYSAPI",$end);
}

$f=fopen("SyscallLookupTable.html","w+");
fwrite($f,$data);
fclose($f);

echo "Done!";
?>