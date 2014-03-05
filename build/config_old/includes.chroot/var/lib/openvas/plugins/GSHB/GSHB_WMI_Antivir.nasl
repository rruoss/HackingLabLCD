###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# WMI AntiVirus Test
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
tag_summary = "Tests WMI AntiVirus Status.";

if(description)
{
  script_id(96011);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WMI Antivirus Status (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Read the WMI Antivirus Status (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "GSHB_WMI_OSInfo.nasl");
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
OSSP = get_kb_item("WMI/WMI_OSSP");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");


if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/Antivir", value:"error");
    set_kb_item(name:"WMI/Antivir/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
     exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/Antivir", value:"error");
  set_kb_item(name:"WMI/Antivir/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}


if(OSVER == '5.1' || (OSVER == '5.2' && OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition' ) ){ # Windows XP

  if(OSSP > 1){ # Windows XP SP2 and greater
      ns = 'root\\SecurityCenter';

      query1 = 'select displayName from AntiVirusProduct';
      query2 = 'select ProductUptoDate from AntiVirusProduct';
      query3 = 'select onAccessScanningEnabled from AntiVirusProduct';

      handle = wmi_connect(host:host, username:usrname, password:passwd, ns:ns);


      if(!handle){
          security_note("wmi_connect: WMI Connect failed.");
          set_kb_item(name:"WMI/Antivir", value:"error");
      exit(0);
      }

      AntiVir_Name = wmi_query(wmi_handle:handle, query:query1);
      AntiVir_UpDate = wmi_query(wmi_handle:handle, query:query2);
      AntiVir_Enable = wmi_query(wmi_handle:handle, query:query3);

      wmi_close(wmi_handle:handle);


 }else{ #Windows XP SP0 and SP1
      Antivir = "Windows XP <= SP1";
 }

}
if((OSVER == '6.0' || OSVER == '6.1' || OSVER == '6.2') && OSTYPE =='1'){ #Windows Vista, Windows 7 and Windows 8

    ns = 'root\\SecurityCenter2';
    query1 = 'select displayName from AntiVirusProduct';
    query2 = 'select productState from AntiVirusProduct';

    handle = wmi_connect(host:host, username:usrname, password:passwd, ns:ns);

    if(!handle){
        security_note("wmi_connect: WMI Connect failed.");
        set_kb_item(name:"WMI/Antivir", value:"error");
        exit(0);
    }

    AntiVir_Name = wmi_query(wmi_handle:handle, query:query1);
    AntiVir_State = wmi_query(wmi_handle:handle, query:query2);

    wmi_close(wmi_handle:handle);

}

if((OSVER == '5.2' || OSVER == '6.0' || OSVER == '6.1' || OSVER == '6.2') && OSTYPE > 1){ #Windows Server 2000, 2003, 2008, 2008 R2 and Server 2012
    Antivir = "Server";
}

if((AntiVir >!< "Server" || AntiVir >!< "Windows XP <= SP1") && !AntiVir_Name) Antivir = "None";
if(!AntiVir && AntiVir_Name) Antivir = "Installed";
if(!AntiVir_Name) AntiVir_Name = "None";
if(!AntiVir_UpDate) AntiVir_UpDate = "None";
if(!AntiVir_Enable) AntiVir_Enable = "None";
if(!AntiVir_State) AntiVir_State = "None";

set_kb_item(name:"WMI/Antivir", value:Antivir);
set_kb_item(name:"WMI/Antivir/Name", value:AntiVir_Name);
set_kb_item(name:"WMI/Antivir/UptoDate", value:AntiVir_UpDate);
set_kb_item(name:"WMI/Antivir/Enable", value:AntiVir_Enable);
set_kb_item(name:"WMI/Antivir/State", value:AntiVir_State);
exit(0);

