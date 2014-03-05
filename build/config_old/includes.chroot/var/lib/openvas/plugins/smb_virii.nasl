# OpenVAS Vulnerability Test
# $Id: smb_virii.nasl 16 2013-10-27 13:09:52Z jan $
# Description: The remote host is infected by a virus
#
# Authors:
# Tenable Network Security
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2005 Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "This script checks for the presence of different virii on the remote
host, by using the SMB credentials you provide OpenVAS with.

- W32/Badtrans-B
- JS_GIGGER.A@mm
- W32/Vote-A
- W32/Vote-B
- CodeRed
- W32.Sircam.Worm@mm
- W32.HLLW.Fizzer@mm
- W32.Sobig.B@mm
- W32.Sobig.E@mm
- W32.Sobig.F@mm
- W32.Sobig.C@mm
- W32.Yaha.J@mm
- W32.mimail.a@mm
- W32.mimail.c@mm
- W32.mimail.e@mm
- W32.mimail.l@mm
- W32.mimail.p@mm
- W32.Welchia.Worm
- W32.Randex.Worm
- W32.Beagle.A
- W32.Novarg.A
- Vesser
- NetSky.C
- Doomran.a
- Beagle.m
- Beagle.j
- Agobot.FO
- NetSky.W
- Sasser
- W32.Wallon.A
- W32.MyDoom.M
- W32.MyDoom.AI
- W32.MyDoom.AX
- W32.Aimdes.B
- W32.Aimdes.C
- W32.ahker.D
- Hackarmy.i
- W32.Erkez.D/Zafi.d
- Winser-A
- Berbew.K
- Hotword.b
- W32.Backdoor.Ginwui.B
- W32.Wargbot
- W32.Randex.GEL
- W32.Fujacks.B";

tag_solution = "See the URLs which will appear in the report";

if(description)
{
 script_id(80043);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C"); 
 script_tag(name:"risk_factor", value:"High");
 name = "The remote host is infected by a virus";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks for the presence of different virii on the remote host";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Tenable Network Security");
 family = "Windows";
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

local_var nname, url, key, item, exp;

if(!get_kb_item("SMB/WindowsVersion")){
 exit(0);
}

if(get_kb_item("SMB/samba"))exit(0);

function check_reg(nname, url, key, item, exp)
{
  if(!registry_key_exists(key:key)){
    return 0;
  } 

  value = registry_get_sz(item:item, key:key);
  if(!value)return 0;

  if(exp == NULL || tolower(exp) >< tolower(value))
  {
   report = string(
"The virus '", nname, "' is present on the remote host\n",
"Solution: ", url);
 
  security_hole(port:kb_smb_transport(), data:report);
 }
}

i = 0;
nname = NULL;

# http://www.infos3000.com/infosvirus/badtransb.htm
nname[i] 	= "W32/Badtrans-B";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.badtrans.b@mm.html";
key[i] 		= "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
item[i] 	= "kernel32";
exp[i]		= "kernel32.exe";

i++;

# http://www.infos3000.com/infosvirus/jsgiggera.htm
nname[i] 	= "JS_GIGGER.A@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/js.gigger.a@mm.html";
key[i] 		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i] 	= "NAV DefAlert";
exp[i]		= NULL;

i ++;

# http://www.infos3000.com/infosvirus/vote%20a.htm
nname[i]	= "W32/Vote-A";
url[i]		= "http://www.sophos.com/virusinfo/analyses/w32vote-a.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "Norton.Thar";
exp[i]		= "zacker.vbs";

i++ ;

nname[i]        = "W32/Vote-B";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.vote.b@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ZaCker";
exp[i]          = "DaLaL.vbs";

i ++;

# http://www.infos3000.com/infosvirus/codered.htm
nname[i]		= "CodeRed";
url[i]		= "http://www.symantec.com/avcenter/venc/data/codered.worm.html";
key[i]		= "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters";
item[i]		= "VirtualRootsVC";
exp[i]		= "c:\,,217";

i ++;

# http://www.infos3000.com/infosvirus/w32sircam.htm
nname[i]		= "W32.Sircam.Worm@mm";
url[i]		= "http://www.symantec.com/avcenter/venc/data/w32.sircam.worm@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]		= "Driver32";
exp[i] 		= "scam32.exe";

i++;

nname[i]  	= "W32.HLLW.Fizzer@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.hllw.fizzer@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemInit";
exp[i]		= "iservc.exe";

i++;

nname[i]  	= "W32.Sobig.B@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.b@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemTray";
exp[i]		= "msccn32.exe";

i ++;

nname[i]		= "W32.Sobig.E@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SSK Service";
exp[i]		= "winssk32.exe";

i ++;

nname[i]		= "W32.Sobig.F@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.f@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "TrayX";
exp[i]		= "winppr32.exe";

i ++;

nname[i]		= "W32.Sobig.C@mm";
url[i]		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "System MScvb";
exp[i]		= "mscvb32.exe";

i ++;

nname[i] 	= "W32.Yaha.J@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.yaha.j@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "winreg";
exp[i]		= "winReg.exe";

i++;

nname[i] 	= "W32.mimail.a@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.a@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "VideoDriver";
exp[i]		= "videodrv.exe";

i++;

nname[i] 	= "W32.mimail.c@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.c@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "NetWatch32";
exp[i]		= "netwatch.exe";

i++;

nname[i] 	= "W32.mimail.e@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.e@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "SystemLoad32";
exp[i]		= "sysload32.exe";

i++;
nname[i] 	= "W32.mimail.l@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.l@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "France";
exp[i]		= "svchost.exe";

i++;
nname[i] 	= "W32.mimail.p@mm";
url[i] 		= "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.p@mm.html";
key[i]		= "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]		= "WinMgr32";
exp[i]		= "winmgr32.exe";

i++;

nname[i]        = "W32.Welchia.Worm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.welchia.worm.html";
key[i]          = "SYSTEM\CurrentControlSet\Services\RpcTftpd";
item[i]         = "ImagePath";
exp[i]          = "%System%\wins\svchost.exe";

i++;

nname[i]        = "W32.Randex.Worm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.b.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "superslut";
exp[i]          = "msslut32.exe";

i++;

nname[i]        = "W32.Randex.Worm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.c.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Microsoft Netview";
exp[i]          = "gesfm32.exe";

i++;

nname[i]        = "W32.Randex.Worm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "mssyslanhelper";
exp[i]          = "msmsgri32.exe";

i++;

nname[i]        = "W32.Randex.Worm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "mslanhelper";
exp[i]          = "msmsgri32.exe";

i ++;
nname[i]        = "W32.Beagle.A";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.a@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "d3update.exe";
exp[i]          = "bbeagle.exe";

i ++;

nname[i]        = "W32.Novarg.A";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.novarg.a@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "TaskMon";
exp[i]          = "taskmon.exe";

i++;

nname[i]        = "Vesser";
url[i]          = "http://www.f-secure.com/v-descs/vesser.shtml";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "KernelFaultChk";
exp[i]          = "sms.exe";

i++;

nname[i]        = "NetSky.C";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.c@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ICQ Net";
exp[i]          = "winlogon.exe";

i++;

nname[i]        = "Doomran.a";
url[i]          = "http://es.trendmicro-europe.com/enterprise/security_info/ve_detail.php?Vname=WORM_DOOMRAN.A";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Antimydoom";
exp[i]          = "PACKAGE.EXE";

i++;

nname[i]        = "Beagle.m";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.m@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "winupd.exe";
exp[i]          = "winupd.exe";

i++;

nname[i]        = "Beagle.j";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.j@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ssate.exe";
exp[i]          = "irun4.exe";

i++;

nname[i]        = "Agobot.FO";
url[i]          = "http://www.f-secure.com/v-descs/agobot_fo.shtml";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "nVidia Chip4";
exp[i]          = "nvchip4.exe";

i ++;
nname[i]        = "NetSky.W";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.w@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "NetDy";
exp[i]          = "VisualGuard.exe";

i++;
nname[i]        = "Sasser";
url[i]          = "http://www.lurhq.com/sasser.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "avserve.exe";
exp[i]          = "avserve.exe";

i++;
nname[i]        = "Sasser.C";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sasser.c.worm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "avserve2.exe";
exp[i]          = "avserve2.exe";

i++;
nname[i]        = "W32.Wallon.A";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.wallon.a@mm.html";
key[i]          = "SOFTWARE\Microsoft\Internet Explorer\Extensions\{FE5A1910-F121-11d2-BE9E-01C04A7936B1}";
item[i]         = "Icon";
exp[i]          = NULL;

i++;
nname[i]        = "W32.MyDoom.M / W32.MyDoom.AX";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ax@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "JavaVM";
exp[i]          = "JAVA.EXE";

i++;
nname[i]        = "W32.MyDoom.AI";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ai@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "lsass";
exp[i]          = "lsasrv.exe";

i++;
nname[i]        = "W32.aimdes.b / W32.aimdes.c";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.aimdes.c@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "MsVBdll";
exp[i]          = "sys32dll.exe";

i++;
nname[i]        = "W32.ahker.d";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.d@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Norton Auto-Protect";
exp[i]          = "ccApp.exe";

i++;
nname[i]        = "Trojan.Ascetic.C";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.ascetic.c.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "SystemBoot";
exp[i]          = "Help\services.exe";

i++;
nname[i]        = "W32.Alcra.A";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.alcra.a.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "p2pnetwork";
exp[i]          = "p2pnetwork.exe";

i++;
nname[i]        = "W32.Shelp";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.shelp.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "explorer";
exp[i]          = "explorer.exe";

# Submitted by David Maciejak
i++;
nname[i]        = "Winser-A";
url[i]          = "http://www.sophos.com/virusinfo/analyses/trojwinsera.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "nortonsantivirus";
exp[i]          = NULL;

i++;
nname[i]        = "Backdoor.Berbew.O";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.o.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
item[i]         = "Web Event Logger";
exp[i]          = "{7CFBACFF-EE01-1231-ABDD-416592E5D639}";

i++;
nname[i]        = "w32.beagle.az";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.az@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Sysformat";
exp[i]          = "sysformat.exe";

i++;
nname[i]        = "Hackarmy.i";
url[i]          = "http://www.zone-h.org/en/news/read/id=4404/";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "putil";
exp[i]          = "%windir%";


i++;
nname[i]        = "W32.Assiral@mm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.assiral@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "MS_LARISSA";
exp[i]          = "MS_LARISSA.exe";

i++;
nname[i]        = "Backdoor.Netshadow";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.netshadow.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Windows Logger";
exp[i]          = "winlog.exe";

i++;
nname[i]        = "W32.Ahker.E@mm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.e@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Generic Host Process for Win32 Services";
exp[i]          = "bazzi.exe";

i++;
nname[i]        = "W32.Bropia.R";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.bropia.r.html";
key[i]          = "Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Wins32 Online";
exp[i]          = "cfgpwnz.exe";

i++;
nname[i]        = "Trojan.Prevert";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.prevert.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Service Controller";
exp[i]          = "%System%\service.exe";

i++;
nname[i]        = "W32.AllocUp.A";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.allocup.a.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = ".msfupdate";
exp[i]          = "%System%\msveup.exe";

i++;
nname[i]        = "W32.Kelvir.M";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.kelvir.m.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "LSASS32";
exp[i]          = "Isass32.exe";

i++;
nname[i]        = "VBS.Ypsan.B@mm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/vbs.ypsan.b@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "BootsCfg";
exp[i]          = "wscript.exe C:\WINDOWS\System\Back ups\Bkupinstall.vbs";

i++;
nname[i]        = "W32.Mytob.AA@mm";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mytob.aa@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "MSN MESSENGER";
exp[i]          = "msnmsgs.exe";

i++;
nname[i]        = "Dialer.Asdplug";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/dialer.asdplug.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ASDPLUGIN";
exp[i]          = "exe -N";

# Submitted by Jeff Adams
i++;
nname[i]        = "W32.Erkez.D/Zafi.D";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.erkez.d@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "Wxp4";
exp[i]          = "Norton Update";

i ++;

nname[i]        = "W32.blackmal.e@mm (CME-24)";
url[i]          = "http://securityresponse.symantec.com/avcenter/venc/data/w32.blackmal.e@mm.html";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "ScanRegistry";
exp[i]          = "scanregw.exe";

i ++;

nname[i]        = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java for Windows XP & NT";
exp[i]          = "javanet.exe";

i ++;

nname[i]        = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java for Windows NT";
exp[i]          = "msjava.exe";

i ++;

nname[i]        = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "MS Java Applets for Windows NT, ME & XP";
exp[i]          = "japaapplets.exe";

i ++;

nname[i]        = "W32.Randex.GEL";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[i]         = "Sun Java Console for Windows NT & XP";
exp[i]          = "jconsole.exe";

i ++;

nname[i]        = "W32.Fujacks.A";
url[i]          = "http://www.symantec.com/enterprise/security_response/writeup.jsp?docid=2006-111415-0546-99";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "svohost";
exp[i]          = "FuckJacks.exe";


i ++;

nname[i]        = "W32.Fujacks.B";
url[i]          = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-112912-5601-99&tabid=2";
key[i]          = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[i]         = "svcshare";
exp[i]          = "spoclsv.exe";

for(i=0;nname[i];i++)
{
  check_reg(nname:nname[i], url:url[i], key:key[i], item:item[i], exp:exp[i]);
}

rootfile = smb_get_systemroot();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system.ini", string:rootfile);

off = 0;
resp = read_file(file:file, share:share, offset:off, count:16384);
if(resp) {
  data = resp;
  while(strlen(resp) >= 16383)
  {
   off += strlen(resp);
   resp = read_file(file:file, share:share, offset:off, count:16384);
   data += resp;
   if(strlen(data) > 1024 * 1024)break;
  }

 if("shell=explorer.exe load.exe -dontrunold" >< data)
 { 
  report = string(
"The virus 'W32.Nimda.A@mm' is present on the remote host\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.nimda.a@mm.html");
 
  security_hole(port:port, data:report);
 }
}
 
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\goner.scr", string:rootfile); 
handle = read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Goner.A@mm' is present on the remote host\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.goner.a@mm.html"); 
 security_hole(port:port, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\winxp.exe", string:rootfile); 
handle = read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Bable.AG@mm' is present on the remote host\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.beagle.ag@mm.html"); 
 security_hole(port:port, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\dnkkq.dll", string:rootfile); 
handle = read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The backdoor 'Backdoor.Berbew.K' is present on the remote host\n",
"Backdoor.Berbew.K is a backdoor which is designed to intercept the logins
and passwords used by the users of the remote host and send them to a 
third party. It usually saves the gathered data in :
	System32\dnkkq.dll
	System32\datakkq32.dll
	System32\kkq32.dll

Delete these files and make sure to disable IE's Autofill feature for important
data (ie: online banking, credit cart numbers, etc...)

Solution: http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.k.html"); 
 security_hole(port:port, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Swen1.dat", string:rootfile); 
handle = read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Swen.A@mm' is present on the remote host\n",
"Solution: http://securityresponse.symantec.com/avcenter/venc/data/w32.swen.a@mm.html"); 
 security_hole(port:port, data:report);
}

# Submitted by Josh Zlatin-Amishav

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile); 
trojanname = raw_string(0xa0, 0x73, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65,0x78, 0x65);

handle = read_file(file:string(file, "\\System32\\",trojanname), share:share, offset:0, count:8);

if (!handle)
handle = read_file(file:string(file, "\\System32\\_svchost.exe"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\Outlook Express"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\CFXP.DRV"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\CHJO.DRV"), share:share, offset:0, count:8);

if (!handle)
handle = read_file(file:string(file, "\\System32\\MMSYSTEM.DLX"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\OLECLI.DLX"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\Windll.dlx"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\Activity.AVI"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\Upgrade.AVI"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\System.lst"), share:share, offset:0, count:8);  

if (!handle)
handle = read_file(file:string(file, "\\System32\\PF30txt.dlx"), share:share, offset:0, count:8);  

if(handle)
{
  report = string(
"The trojan 'hotword' is present on the remote host\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.hotword.html\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.rona.html\n",
"Solution:  Use latest anti-virus signatures to clean the machine."); 
  security_hole(port:port, data:report);
}

# Submitted by David Maciejak

sober = make_list("nonzipsr.noz",
"clonzips.ssc",
"clsobern.isc",
"sb2run.dii",
"winsend32.dal",
"winroot64.dal",
"zippedsr.piz",
"winexerun.dal",
"winmprot.dal",
"dgssxy.yoi",
"cvqaikxt.apk",
"sysmms32.lla",
"Odin-Anon.Ger");

foreach f (sober)
{
 file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\" + f, string:rootfile); 
 handle = read_file(file:file, share:share, offset:0, count:8);  
 if(handle)
 {
  report = string(
"The virus 'Sober.i@mm' is present on the remote host\n",
"Solution: http://securityresponse.symantec.com/avcenter/venc/data/w32.sober.i@mm.html"); 
  security_hole(port:port, data:report);
  break;
 }
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\wgareg.exe", string:rootfile); 
handle = read_file(file:file, share:share, offset:0, count:8);
if(handle)
{
 report = string(
"The virus 'W32.Wargbot@mm' is present on the remote host\n",
"Solution: http://www.symantec.com/security_response/writeup.jsp?docid=2006-081312-3302-99"); 
 security_hole(port:port, data:report);
}

# Submitted by Josh Zlatin-Amishav

foreach f (make_list("zsydll.dll", "zsyhide.dll"))
{
 file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\" + f, string:rootfile);
 handle = read_file(file:file, share:share, offset:0, count:8);
 if(handle)
 {
   report = string(
   "The backdoor 'W32.Backdoor.Ginwui.B' is present on the remote host\n",
   "See also : http://securityresponse.symantec.com/avcenter/venc/data/backdoor.ginwui.b.html\n",
   "Solution:  Use latest anti-virus signatures to clean the machine.");
   security_hole(port:port, data:report);
   break;
 }
}

exit(0);
