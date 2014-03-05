###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Pre-Windows 2000 Compatible Access (win)
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
tag_summary = "The scripte check, if
  Everyone in the Usergroup Pre-Windows 2000 Compatible Access.";

if(description)
{
  script_id(96040);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Pre-Windows 2000 Compatible Access (win)");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Pre-Windows 2000 Compatible Access (win)");
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

include("wmi_user.inc");

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");


if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/AdminUsers", value:"error");
    set_kb_item(name:"WMI/AdminUsers/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
    set_kb_item(name:"WMI/AdminUsers", value:"error");
    set_kb_item(name:"WMI/AdminUsers/log", value:"wmi_connect: WMI Connect failed.");
    wmi_close(wmi_handle:handle);
    exit(0);
}

Everyone = "None";
PreWin2000 = "None";

sysLst = wmi_user_sysaccount(handle);
usrLst = wmi_user_useraccount(handle);
grpLst = wmi_user_group(handle);
usrgrplist = wmi_user_groupuser(handle:handle);

Lst = sysLst + usrLst + grpLst;

Lst = split(Lst, "\n", keep:0);
for(i=1; i<max_index(Lst); i++)
{
  if("Domain|Name|SID" >< Lst[i]){
    continue;
  }
  desc = split(Lst[i], sep:"|", keep:0);
  if(desc !=NULL)
  {
        if(desc[2] == "S-1-1-0") Everyone = desc[1];
        if(desc[2] == "S-1-5-32-554") PreWin2000 = desc[1];
  }
}

usrgrplist = split(usrgrplist, sep:'\n', keep:0);

for(u=1; u<max_index(usrgrplist); u++)
{
  usrgrplistinf = split(usrgrplist[u], sep:"|", keep:0);
  PreGrpLst = eregmatch(pattern:PreWin2000, string:usrgrplistinf[0]);
  if (PreWin2000 == PreGrpLst[0])
  {
    PreUsrLst = eregmatch(pattern:Everyone, string:usrgrplistinf[1]);
    PreWin2000Usr = PreUsrLst[0];
  }
}

if(!PreWin2000Usr) PreWin2000Usr = "None";

set_kb_item(name:"WMI/PreWin2000Usr", value:PreWin2000Usr);

wmi_close(wmi_handle:handle);
exit(0);
