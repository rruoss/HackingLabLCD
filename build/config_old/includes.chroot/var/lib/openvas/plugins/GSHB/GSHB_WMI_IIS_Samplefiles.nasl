###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IIS_Samplefiles.nasl 9 2013-10-27 09:38:41Z jan $
#
# IIS Samplefiles and Scripte (Win)
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
tag_summary = "The script detects if IIS Samplefiles and Scripte are installed.";


if(description)
{
  script_id(96008);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IIS Samplefiles and Scripte (Win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check if IIS Samplefiles and Scripte are installed.");
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
include("wmi_os.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");


if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/IIS-Samplefiles", value:"error");
    set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/IIS-Samplefiles", value:"error");
  set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\InetStp", val_name:"MajorVersion");

if(!IISVER){
    set_kb_item(name:"WMI/IIS-Samplefiles", value:"off");
    set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"IT-Grundschutz: No IIS installed, Test not needed!");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

sysdirpath = wmi_os_sysdir(handle:handle);

ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir (x86)");

if (!ProgramDir){
  ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir");
}

val01 = split(ProgramDir, sep:"\", keep:0);

if (OSVER < 6)
{
  val11 = split(sysdirpath, sep:"|", keep:0);
  val12 = split(val11[4], sep:"\", keep:0);
  val13 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val12[2]);
  syspath = "\\" + val12[1] + "\\" + val13[0] + "\\";
}
else
{
  val11 = split(sysdirpath, sep:":", keep:0);
  val13 = eregmatch(pattern:".*[A-Za-z0-9-_///./(/)!$%&=+#@~^]", string:val11[1]);
  val13 = split(val13[0], sep:"\", keep:0);
  syspath = "\\" + val13[1] + "\\" + val13[2] + "\\";
}

filespec1 = "\\Inetpub\\iissamples\\";
filespec2 = "\\Inetpub\\iissamples\\sdk\\";
filespec3 = "\\Inetpub\\AdminScripts\\";
filespec4 = "\\" + val01[1] + "\\" + "Common Files\\System\\msadc\\Samples\\";
filespec5 = syspath + "inetsrv\\iisadmpwd\\";

r1 = wmi_file_filelist(handle:handle, dirPath:filespec1);
r2 = wmi_file_filelist(handle:handle, dirPath:filespec2);
r3 = wmi_file_filelist(handle:handle, dirPath:filespec3);
r4 = wmi_file_filelist(handle:handle, dirPath:filespec4);
r5 = wmi_file_filelist(handle:handle, dirPath:filespec5);

if( r1 || r2 || r3 || r4 || r5) {
   set_kb_item(name:"WMI/IIS-Samplefiles", value:"on");
   if (r1) set_kb_item(name:"WMI/IIS-Samplefiles/iissamples", value:"on");
   if (r2) set_kb_item(name:"WMI/IIS-Samplefiles/iissdk", value:"on");
   if (r3) set_kb_item(name:"WMI/IIS-Samplefiles/iisadminscripts", value:"on");
   if (r4) set_kb_item(name:"WMI/IIS-Samplefiles/iismsadc", value:"on");
   if (r5) set_kb_item(name:"WMI/IIS-Samplefiles/iissdmpwd", value:"on");
   } else { set_kb_item(name:"WMI/IIS-Samplefiles", value:"off");
}
wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
