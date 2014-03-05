###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Find OS/2 and Posix Subsystem over WMI (win)
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
tag_summary = "Find OS/2 and Posix Subsystem over WMI (win)";

if(description)
{
  script_id(96007);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Find OS/2 and Posix Subsystem over WMI (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Find OS/2 and Posix Subsystem over WMI (win)");
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
win_dir = get_kb_item("WMI/WMI_OSWINDIR");
win_dir = split(win_dir, sep:":", keep:0);
win_dir = win_dir[0] + ':\\' + win_dir[1];

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/SessionManagerOS2", value:"error");
    set_kb_item(name:"WMI/SessionManagerPosix", value:"error");
    set_kb_item(name:"WMI/SessionManager/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/SessionManagerOS2", value:"error");
  set_kb_item(name:"WMI/SessionManagerPosix", value:"error");
  set_kb_item(name:"WMI/SessionManager/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

if (OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
    set_kb_item(name:"WMI/SessionManagerOS2", value:"error");
    set_kb_item(name:"WMI/SessionManagerPosix", value:"error");
    set_kb_item(name:"WMI/SessionManager/log", value:"The System is an " + OSNAME + " System");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

if(!isnull(win_dir))
{
  filespec1 = win_dir+"\\system32\\os2.exe";
  filespec2 = win_dir+"\\system32\\os2srv.exe";
  filespec3 = win_dir+"\\system32\\os2ss.exe";
  r1 = wmi_file_check_file_exists(handle:handle, filePath:filespec1);
  r2 = wmi_file_check_file_exists(handle:handle, filePath:filespec2);
  r3 = wmi_file_check_file_exists(handle:handle, filePath:filespec3);
        if( r1 == "1" && r2 == "1" && r3 == "1") {
                set_kb_item(name:"WMI/OS2", value:"on");
                } else {  set_kb_item(name:"WMI/OS2", value:"off");
        }
}else {
        log_message(port:0, proto: "IT-Grundschutz", data:string("Error getting SMB-File -> "+get_kb_item("SMB/ERROR")) + string("\n"));
        set_kb_item(name:"WMI/OS2", value:"error");
      }

if(!isnull(win_dir))
{
  filespec1 = win_dir+"\\system32\\psxdll.dll";
  filespec2 = win_dir+"\\system32\\pax.exe";
  filespec3 = win_dir+"\\system32\\posix.exe";
  filespec4 = win_dir+"\\system32\\psxss.exe";
  r1 = wmi_file_check_file_exists(handle:handle, filePath:filespec1);
  r2 = wmi_file_check_file_exists(handle:handle, filePath:filespec2);
  r3 = wmi_file_check_file_exists(handle:handle, filePath:filespec3);
  r4 = wmi_file_check_file_exists(handle:handle, filePath:filespec4);
        if( r1 == "1" && r2 == "1" && r3 == "1" && r4 == "1") {
                set_kb_item(name:"WMI/Posix", value:"on");
                } else {  set_kb_item(name:"WMI/Posix", value:"off");
        }
}else {
        log_message(port:0, proto: "IT-Grundschutz", data:string("Error getting SMB-File -> "+get_kb_item("SMB/ERROR")) + string("\n"));
        set_kb_item(name:"WMI/Posix", value:"error");
      }

keyexist = wmi_reg_enum_value(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems");

if(!keyexist){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/SessionManagerOS2", value:"error");
  set_kb_item(name:"WMI/SessionManagerPosix", value:"error");
exit(0);
}

OS2 = wmi_reg_get_sz(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems", key_name:"Os2");

posix = wmi_reg_get_sz(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems", key_name:"Posix");

if(OS2) {
  set_kb_item(name:"WMI/SessionManagerOS2", value:"on");
}else{
  set_kb_item(name:"WMI/SessionManagerOS2", value:"off");
}

if(posix) {
  set_kb_item(name:"WMI/SessionManagerPosix", value:"on");
}else{
  set_kb_item(name:"WMI/SessionManagerPosix", value:"off");
}

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);
exit(0);

