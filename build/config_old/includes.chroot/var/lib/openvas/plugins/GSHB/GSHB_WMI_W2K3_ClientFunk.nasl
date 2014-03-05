###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Find Windows 2003 Client Funktionality over WMI (win)
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
tag_summary = "Find Windows 2003 Client Funktionality over WMI:

 Nettmeeting
 OutlookExpress
 Windows Media Player";

if(description)
{
  script_id(96018);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Find Windows 2003 Client Funktionality over WMI (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Find Windows 2003 Client Funktionality over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("wmi_file.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

if (OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
    set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"inapplicable");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir (x86)");

if (!ProgramDir){
  ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir");
}

val01 = split(ProgramDir, sep:"\", keep:0);
path = val01[0] + "\\" + val01[1] + "\\";

ExistNetMeeting = wmi_file_check_file_exists(handle:handle, filePath:path + "NetMeeting\\conf.exe"  );
if(ExistNetMeeting == "1"){
    ExistNetMeeting = val01[0] + "\" + val01[1] + "\" + "NetMeeting\conf.exe ;";
}

ExistOutlookExpress = wmi_file_check_file_exists(handle:handle, filePath:path + "Outlook Express\\msimn.exe"  );
if(ExistOutlookExpress == "1"){
    ExistOutlookExpress = val01[0] + "\" + val01[1] + "\" + "Outlook Express\msimn.exe ;";
}

ExistMediaplayer = wmi_file_check_file_exists(handle:handle, filePath:path + "Windows Media Player\\wmplayer.exe"  );
if(ExistMediaplayer == "1"){
    ExistMediaplayer = val01[0] + "\" + val01[1] + "\" + "Windows Media Player\wmplayer.exe ;";
}


if(ExistNetMeeting)set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:ExistNetMeeting);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"None");

if(ExistOutlookExpress)set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:ExistOutlookExpress);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"None");

if(ExistMediaplayer)set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:ExistMediaplayer);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"None");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
