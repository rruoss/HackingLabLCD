###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Read over WMI the Windows Password Policie (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
# Thomas Rotter<T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This scipt read over WMI the Windows Password Policie configuration";


if(description)
{
  script_id(96033);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read over WMI the Windows Password Policie (Win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Read over WMI the Windows Password Policie");
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

include("wmi_rsop.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
domain = get_kb_item("SMB/domain");
domfil = get_kb_item("SMB/domain_filled/0");
OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/lockoutpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

#if(WindowsDomainrole == "4" || WindowsDomainrole == "5")
  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
#else 
#  handle = wmi_connect_rsop(host:host, username:usrname, password:passwd);
  
if(!handle){
  set_kb_item(name:"WMI/lockoutpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy", value:"error");
#  set_kb_item(name:"WMI/passwdpolicy/log", value:"wmi_connect_rsop: WMI Connect failed.");
  set_kb_item(name:"WMI/passwdpolicy/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}


pwdList = wmi_rsop_passwdpolicy(handle);


if(pwdList != NULL)
{
  pwdList = split(pwdList, "\n", keep:0);
  for(i=1; i<max_index(pwdList); i++)
  {
    desc = split(pwdList[i], sep:"|", keep:0);
    if(desc != NULL){
      set_kb_item(name:"WMI/passwdpolicy/" + desc[4], value:desc[7]);
    }
  }
}
else
{
  set_kb_item(name:"WMI/passwdpolicy", value:"False");
}

lkList = wmi_rsop_lockoutpolicy(handle);
if(lkList != NULL)
{
  lkList = split(lkList, "\n", keep:0);
  for(i=1; i<max_index(lkList); i++)
  {
    desc = split(lkList[i], sep:"|", keep:0);
    if(desc != NULL){
      set_kb_item(name:"WMI/lockoutpolicy/" + desc[4], value:desc[7]);
    }
  }
}
else
{
  set_kb_item(name:"WMI/lockoutpolicy", value:"False");
}

wmi_close(wmi_handle:handle);

set_kb_item(name:"WMI/lockoutpolicy/stat", value:"ok");
set_kb_item(name:"WMI/passwdpolicy/stat", value:"ok");

exit(0);
