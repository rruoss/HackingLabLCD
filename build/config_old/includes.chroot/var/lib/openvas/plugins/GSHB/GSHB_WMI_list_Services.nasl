###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Get all Windows non System Services, Service start modes and Eventlog Servicestate over WMI (win)
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
tag_summary = "Get all Windows non System Services,

  Service start modes and Eventlog Servicestate over WMI.";

if(description)
{
  script_id(96028);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get all Windows non System Services, Service start modes and Eventlog Servicestate over WMI (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Get all Windows non System Services, Service start modes and Eventlog Servicestate over WMI (win)");
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

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/EventLogService", value:"error");
    set_kb_item(name:"WMI/nonSystemServices", value:"error");
    set_kb_item(name:"WMI/EventLogService/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
    set_kb_item(name:"WMI/EventLogService", value:"error");
    set_kb_item(name:"WMI/nonSystemServices", value:"error");
    set_kb_item(name:"WMI/EventLogService/log", value:"wmi_connect: WMI Connect failed.");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}


query1 = 'select startname, state  from Win32_Service WHERE NOT StartName LIKE "NT AUTHORITY%" AND NOT StartName = "LocalSystem"';
query2 = 'select state  from Win32_Service WHERE NAME = "eventlog"';
query3 = 'select Name, StartMode from Win32_Service';

nonSystemServices = wmi_query(wmi_handle:handle, query:query1);
EventLogService = wmi_query(wmi_handle:handle, query:query2);
ServiceStartmode = wmi_query(wmi_handle:handle, query:query3);

if(!nonSystemServices) nonSystemServices = "None";
if(!EventLogService) EventLogService = "None";
if(!ServiceStartmode) ServiceStartmode = "None";

set_kb_item(name:"WMI/EventLogService", value:EventLogService);
set_kb_item(name:"WMI/nonSystemServices", value:nonSystemServices);
set_kb_item(name:"WMI/ServiceStartmode", value:ServiceStartmode);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
