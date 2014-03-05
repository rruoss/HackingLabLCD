###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Last username (Win)
#
# Authors:
# Thomas Rotter<T.Rotter@dn-systems.de>
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
tag_summary = "The script detects if Last Login Username an Loginwarning is displayed.";


if(description)
{
  script_id(96005);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-12-01 10:53:45 +0100 (Wed, 01 Dec 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Last Username (Win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check if Last Login Username and Loginwarning Displayed.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB");
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
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"error");
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"error");
  set_kb_item(name:"WMI/LegalNoticeText", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:string("No access to SMB host. Firewall is activated or there is not a Windows system."));
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  security_note("wmi_connect_reg: WMI Connect failed.");
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"error");
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"error");
  set_kb_item(name:"WMI/LegalNoticeText", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}

WINLOGONKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
POLICIEKEY = wmi_reg_enum_value(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");

if(!WINLOGONKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"error");
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"error");
  set_kb_item(name:"WMI/LegalNoticeText", value:"error");
exit(0);
}

lastuser = wmi_reg_get_dword_val(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", val_name:"DontDisplayLastUserName");

lastuserpol = wmi_reg_get_dword_val(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"DontDisplayLastUserName");

lenoca = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"LegalNoticeCaption");

lenocapol = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", key_name:"LegalNoticeCaption");

lenote = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"LegalNoticeText");

lenotepol = wmi_reg_get_sz(wmi_handle:handle, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", key_name:"legalnoticetext");

if(!POLICIEKEY){
lastuserpol = 0;
lenocapol = "";
lenotepol = "";
}

if((lastuser == 1) || (lastuserpol == 1))
{
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"on");
}
else  {
      if((lastuser != 1) && (lastuserpol == 1))
              {
              set_kb_item(name:"WMI/DontDisplayLastUserName", value:"on");
              }
      else    {set_kb_item(name:"WMI/DontDisplayLastUserName", value:"off");
              }
}


if(lenoca >< "" && lenocapol >< "") {
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"off");
}else{
set_kb_item(name:"WMI/LegalNoticeCaption", value:"on");
}

if(lenote >< "" && lenotepol >< "") {
  set_kb_item(name:"WMI/LegalNoticeText", value:"off");
}else{
  set_kb_item(name:"WMI/LegalNoticeText", value:"on");
}
wmi_close(wmi_handle:handle);
exit(0);
