###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_CD-FD-User-only-access.nasl 9 2013-10-27 09:38:41Z jan $
#
# CD-ROM and FDD local User only access
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
tag_summary = "The script detects whether only local users on CD-ROM and FDD can access.";


if(description)
{
  script_id(96002);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CD-ROM and FDDlocal User only access (Win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check for CD-ROM and FDD local User only access.");
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
  set_kb_item(name:"WMI/CD_Allocated", value:"error");
  set_kb_item(name:"WMI/FD_Allocated", value:"error");
  set_kb_item(name:"WMI/CD_Allocated/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  security_note("wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/CD_Allocated", value:"error");
  set_kb_item(name:"WMI/FD_Allocated", value:"error");
  set_kb_item(name:"WMI/CD_Allocated/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

ALLOCDKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");

if(!ALLOCDKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/CD_Allocated", value:"error");
  set_kb_item(name:"WMI/FD_Allocated", value:"error");
  set_kb_item(name:"WMI/CD_Allocated/log", value:"IT-Grundschutz: Registry Path not found.");
  wmi_close(wmi_handle:handle);
  exit(0);
}
else if ("allocatecdroms" >!< ALLOCDKEY || "allocatefloppies" >!< ALLOCDKEY)
{
  if ("allocatecdroms" >!< ALLOCDKEY) allocd = "false";
  if ("allocatefloppies" >!< ALLOCDKEY) allofd = "false";
}


if(!allocd) allocd = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"allocatecdroms");

if(!allofd) allofd = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"allocatefloppies");


if(allocd == "false"){
  set_kb_item(name:"WMI/CD_Allocated", value:"off");
} else if(allocd == "0"){
  set_kb_item(name:"WMI/CD_Allocated", value:"off");
} else if(allocd == 1){
  set_kb_item(name:"WMI/CD_Allocated", value:"on");
} else if (allocd >< "error"){
  set_kb_item(name:"WMI/CD_Allocated", value:"error");
  set_kb_item(name:"WMI/CD_Allocated/log", value:"IT-Grundschutz: Registry Value 'allocatecdroms' not found.");
}


if(allofd == "false"){
  set_kb_item(name:"WMI/FD_Allocated", value:"off");
} else if(allofd == "0"){
  set_kb_item(name:"WMI/FD_Allocated", value:"off");
} else if(allofd == 1){
  set_kb_item(name:"WMI/FD_Allocated", value:"on");
} else if (allofd >< "error"){
  set_kb_item(name:"WMI/FD_Allocated", value:"error");
  set_kb_item(name:"WMI/FD_Allocated/log", value:"IT-Grundschutz: Registry Value 'allocatecdroms' not found.");
}

wmi_close(wmi_handle:handle);

exit(0);
