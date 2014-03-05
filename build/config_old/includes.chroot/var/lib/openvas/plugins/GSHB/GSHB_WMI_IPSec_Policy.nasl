###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IPSec_Policy.nasl 9 2013-10-27 09:38:41Z jan $
#
# Check over WMI if IPSec Policy used for Windows (Win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "The script detects over WMI if IPSec Policy used under Windows
2000 and XP.";

if(description)
{
  script_id(96042);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Mon Nov 09 14:03:22 2009 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check over WMI if IPSec Policy used for Windows (Win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check over WMI if IPSec Policy used for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
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
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/IPSecPolicy", value:"error");
  set_kb_item(name:"WMI/IPSecPolicy/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  set_kb_item(name:"WMI/IPSecPolicy", value:"error");
  set_kb_item(name:"WMI/IPSecPolicy/log", value:"wmi_connect: WMI Connect failed.");
  exit(0);
}

GPTIPSECPolicy = wmi_reg_enum_value(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy");

if (OSVER < 6){
  NoDefaultExempt = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\IPSEC", val_name:"NoDefaultExempt");
  if (!NoDefaultExempt) NoDefaultExempt = "-1";
}else{
  NoDefaultExempt = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\PolicyAgent", val_name:"NoDefaultExempt");
  if (!NoDefaultExempt) NoDefaultExempt = "-1";
}
if(!GPTIPSECPolicy){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path 'SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy' not found.");
  set_kb_item(name:"WMI/IPSecPolicy", value:"off");
  set_kb_item(name:"WMI/NoDefaultExempt", value:NoDefaultExempt);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

#if (OSVER == '5.0' ||  OSVER == '5.1' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition')
#{
  if (GPTIPSECPolicy)
  {
    if (OSVER < 6){
      DomPolicyPath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy", key_name:"DSIPSECPolicyPath");

      DomPolicyPath = split(DomPolicyPath, sep:",", keep:0);
      DomPolicyPath = ereg_replace(pattern:'LDAP://CN=ipsecPolicy',replace:'', string:DomPolicyPath[0]);
      key = "SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecPolicy" + DomPolicyPath;
      ActiveDomPolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:key, key_name:"ipsecName");
    }else{
      ActiveDomPolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\GPTIPSECPolicy", key_name:"DSIPSECPolicyName");
    }
    set_kb_item(name:"WMI/IPSecPolicy", value:ActiveDomPolicy);
  }
  else
  {
    PolicyPath = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local", key_name:"ActivePolicy");
    ActivePolicy = wmi_reg_get_sz(wmi_handle:handlereg, key:PolicyPath, key_name:"ipsecName");
    set_kb_item(name:"WMI/IPSecPolicy", value:ActivePolicy);
  }

  if (!ActiveDomPolicy && !ActivePolicy) set_kb_item(name:"WMI/IPSecPolicy", value:"off");
  set_kb_item(name:"WMI/NoDefaultExempt", value:NoDefaultExempt);
  wmi_close(wmi_handle:handlereg);
  exit(0);

#}
#else
#{
#  set_kb_item(name:"WMI/IPSecPolicy", value:"inapplicable");
#  log_message(port:0, proto: "IT-Grundschutz", data:string("No Windows 2000 or Windows XP"));
#  exit(0);
#}
