###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Get Windows Eventlog Entries over WMI
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
tag_summary = "Get Windows Eventlog Entries over WMI";

if(description)
{
  script_id(96204);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Get Windows Eventlog Entries over WMI");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Get Windows Eventlog Entries over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("Tools/Present/wmi");
  script_dependencies("toolcheck.nasl", "smb_login.nasl");
  script_add_preference(name:"Maximum number of log lines", type:"entry", value:"0");
  script_require_keys("SMB/login","SMB/password");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


RecNumber = script_get_preference("Maximum number of log lines");
if (RecNumber <= 0) exit(0);
if (RecNumber > 100) RecNumber = 100;


host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");

if(!host || !usrname || !passwd){
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  wmi_close(wmi_handle:handle);
  exit(0);
}

AppRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber from Win32_NTLogEvent WHERE LogFile='Application'");
AppRecNumber = split(AppRecNumber, keep:0);
var = split(AppRecNumber[1], sep:"|", keep:0);
AppFirstRecNumber = var[1];

SecRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber from Win32_NTLogEvent WHERE LogFile='Security'");
SecRecNumber = split(SecRecNumber, keep:0);
var = split(SecRecNumber[1], sep:"|", keep:0);
SecFirstRecNumber = var[1];

SysRecNumber = wmi_query(wmi_handle:handle, query:"SELECT RecordNumber from Win32_NTLogEvent WHERE LogFile='System'");
SysRecNumber = split(SysRecNumber, keep:0);
var = split(SysRecNumber[1], sep:"|", keep:0);
SysFirstRecNumber = var[1];

set_kb_item(name:"WMI/SysFirstRecNumber", value:SysFirstRecNumber);#TEST

if(AppFirstRecNumber != "1"){
  if (int(AppFirstRecNumber) > int(RecNumber)){
    AppRecNumber = int(AppFirstRecNumber) - int(RecNumber);
  }else{
    AppRecNumber = int(AppFirstRecNumber);
  }
  set_kb_item(name:"WMI/AppRecNumber", value:AppRecNumber);#TEST
  AppQuery = "SELECT * from Win32_NTLogEvent WHERE LogFile='Application' and RecordNumber >= '" + AppRecNumber + "'";
  Application = wmi_query(wmi_handle:handle, query:AppQuery);
}

if(SecFirstRecNumber != "1"){
  if (int(SecFirstRecNumber) > int(RecNumber)){
    SecRecNumber = int(SecFirstRecNumber) - int(RecNumber);
  }else{
    SecRecNumber = int(SecFirstRecNumber);
  }
  SecQuery = "SELECT * from Win32_NTLogEvent WHERE LogFile='Security' and RecordNumber >= '" + SecRecNumber + "'";
  Security = wmi_query(wmi_handle:handle, query:SecQuery);
}

if(SysFirstRecNumber != "1"){
  if (int(SysFirstRecNumber) > int(RecNumber)){
    SysRecNumber = int(SysFirstRecNumber) - int(RecNumber);
  }else{
    SysRecNumber = int(SysFirstRecNumber);
  }
  SysQuery = "SELECT * from Win32_NTLogEvent WHERE LogFile='System' and RecordNumber >= '" + SysRecNumber + "'";
  System = wmi_query(wmi_handle:handle, query:SysQuery);
}

if (Application)log_message(port:0, proto: "MS-Eventlog/Application", data:Application);
if (Security)log_message(port:0, proto: "MS-Eventlog/Security", data:Security);
if (System)log_message(port:0, proto: "MS-Eventlog/System", data:System);

exit(0);
