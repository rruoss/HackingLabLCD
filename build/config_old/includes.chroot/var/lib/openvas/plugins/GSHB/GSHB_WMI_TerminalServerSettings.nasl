###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_TerminalServerSettings.nasl 9 2013-10-27 09:38:41Z jan $
#
# Get Windows Terminal Server Settings
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "The script reads the Windows Terminal Server Settings.";


if(description)
{
  script_id(96213);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-12-14 11:30:03 +0100 (Wed, 14 Dec 2011)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows Terminal Server Settings");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check for Get Windows Terminal Server Settings.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
  script_dependencies("toolcheck.nasl", "GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");
    
if(!OSVER || OSVER >< "none"){
  error = get_kb_item("WMI/WMI_OS/log");
  set_kb_item(name:"WMI/TerminalService", value:"error");
  if (error)set_kb_item(name:"WMI/TerminalService/log", value:error);
  else set_kb_item(name:"WMI/TerminalService/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/TerminalService", value:"error");
  set_kb_item(name:"WMI/TerminalService/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

query = 'select * from Win32_TerminalServiceSetting';

TSS = wmi_query(wmi_handle:handle, query:query);

if(!TSS) TSS = "none";

set_kb_item(name:"WMI/TerminalService", value:TSS);


wmi_close(wmi_handle:handle);
exit(0);

