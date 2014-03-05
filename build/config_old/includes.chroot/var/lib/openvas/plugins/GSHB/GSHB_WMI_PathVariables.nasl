###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Windows Path Variable over WMI (win)
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
tag_summary = "Read the Windows System Path Varibles over WMI.";

if(description)
{
  script_id(96032);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Path Variable over WMI (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Windows Path Variable over WMI (win)");
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

include("wmi_os.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/WinPathVar", value:"error");
  set_kb_item(name:"WMI/WinPathVar/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  set_kb_item(name:"WMI/WinPathVar", value:"error");
  set_kb_item(name:"WMI/WinPathVar/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

PathVar = wmi_reg_get_ex_string_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", val_name:"Path");


if(!PathVar)
{
  handle = wmi_connect(host:host, username:usrname, password:passwd);
  OSWINDIR = get_kb_item("WMI/WMI_OSWINDIR");
  query = "select VariableValue from Win32_Environment WHERE Name = 'path'";
  PathVar = wmi_query(wmi_handle:handle, query:query);
  PathVar = split(PathVar, sep:"|", keep:0);
  PathVar = ereg_replace(pattern:'%SystemRoot%', string:PathVar[4], replace:OSWINDIR);
  PathVar = ereg_replace(pattern:'\n', string:PathVar, replace:'');

  wmi_close(wmi_handle:handle);

  if(!PathVar)PathVar = "None";
}


set_kb_item(name:"WMI/WinPathVar", value:PathVar);

wmi_close(wmi_handle:handlereg);

exit(0);
