###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Find Windows Admin Tools over WMI if IIS installed(win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Vista with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "If IIS installed, find Windows Admin Tools over WMI:

 arp.exe, at.exe, atsvc.exe, cacls.exe, cmd.exe,
 cscript.exe, debug.exe, edit.com, edlin.exe, ftp.exe, finger.exe,
 ipconfig.exe, net.exe, netsh.exe, netstat.exe, nslookup.exe,
 ping.exe, poledit.exe, posix.exe, qbasic.exe, rcp.exe, rdisk.exe,
 regedit.exe, regedt32.exe, regini.exe, regsrv3.exe, rexec.exe,
 route.exe, rsh.exe, runonce.exe, secfixup.exe, syskey.exe,
 telnet.exe, tftp.exe, tracert.exe, tskill.exe, wscript.exe,
 xcopy.exe";

if(description)
{
  script_id(96016);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Find Windows Admin Tools over WMI if IIS installed (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Find Windows Admin Tools over WMI if IIS installed(win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_IIS_OpenPorts.nasl", "GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("wmi_file.inc");
include("wmi_os.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
IISVER  = get_kb_item("WMI/IISandPorts");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/AdminTools", value:"error");
    set_kb_item(name:"WMI/AdminTools/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/AdminTools", value:"error");
  set_kb_item(name:"WMI/AdminTools/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

windirpath = wmi_os_windir(handle:handle);
sysdirpath = wmi_os_sysdir(handle:handle);

if(IISVER >< "None"){
    set_kb_item(name:"WMI/AdminTools", value:"inapplicable");
    set_kb_item(name:"WMI/AdminTools/log", value:"IT-Grundschutz: No IIS installed, Test not needed!");
    wmi_close(wmi_handle:handle);
    exit(0);
}

program = make_list("arp.exe", "at.exe", "atsvc.exe", "cacls.exe", "cmd.exe",
 "cscript.exe", "debug.exe", "edit.com", "edlin.exe", "ftp.exe", "finger.exe",
 "ipconfig.exe", "net.exe", "netsh.exe", "netstat.exe", "nslookup.exe",
 "ping.exe", "poledit.exe", "posix.exe", "qbasic.exe", "rcp.exe", "rdisk.exe",
 "regedit.exe", "regedt32.exe", "regini.exe", "regsrv3.exe", "rexec.exe",
 "route.exe", "rsh.exe", "runonce.exe", "secfixup.exe", "syskey.exe",
 "telnet.exe", "tftp.exe", "tracert.exe", "tskill.exe", "wscript.exe",
 "xcopy.exe");

if (OSVER < 6){
val01 = split(windirpath, sep:"|", keep:0);
val02 = split(val01[4], sep:"\", keep:0);
val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
path = val02[0] + "\\" + val03[0] + "\\";
}
else {
val01 = split(windirpath, sep:":", keep:0);
val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val01[1]);
val04 = eregmatch(pattern:"[A-Z]$", string:val01[0]);
path = val04[0] + ":\" + val03[0] + "\\";
}

if (OSVER < 6){
val11 = split(sysdirpath, sep:"|", keep:0);
val12 = split(val11[4], sep:"\", keep:0);
val13 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val12[2]);
syspath = val12[0] + "\\" + val12[1] + "\\" + val13[0] + "\\";
}
else {
val11 = split(sysdirpath, sep:":", keep:0);
val13 = eregmatch(pattern:".*[A-Za-z0-9-_///./(/)!$%&=+#@~^]", string:val11[1]);
val13 = split(val13[0], sep:"\", keep:0);
val15 = eregmatch(pattern:"[A-Z]$", string:val11[0]);
syspath = val15[0] + ":\\" + val13[1] + "\\" + val13[2] + "\\";
}


foreach p (program) {
  fileExist = wmi_file_check_file_exists(handle:handle, filePath:path + p);
  if(fileExist == "1"){
    if (OSVER < 6) note = note + val02[0] + "\" + val03[0] + "\" + p + '\n';
    if (OSVER >= 6)note = note + val04[0] + ":\" + val03[0] + "\" + p + '\n';
  }
  fileExist = wmi_file_check_file_exists(handle:handle, filePath:syspath + p);
  if(fileExist == "1"){
    if (OSVER < 6) note = note + val12[0] + "\" + val13[0] + "\" + p + '\n';
    if (OSVER >= 6)note = note + val15[0] + ":\" + val13[1] + "\" + val13[2] + "\" + p + '\n';
  }
}

if(note)set_kb_item(name:"WMI/AdminTools", value:note);
else set_kb_item(name:"WMI/AdminTools", value:"None");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
