###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_reg_service_pack.nasl 64 2013-11-13 15:57:06Z veerendragg $
# Description: SMB Registry : Windows Service Pack version
#
# Authors:
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#  Date Written: 2008/07/07
#  Revision: 1.5
#
#  Log: Modified by SecPod.
#  Issue #03 (By schandan)
#  Modified to support Win2K and Win2003 ServicePack Version.
#
#  Updated By: Antu Sanadi <santu@secpod.com> on 2010-08-20
#  - Enhanced the code to support Windows Vista Service packs.
#  - Enhaned the code to support Windows 7 service packs.
#  - Enhaned the code to support Windows server 2008.
#  - Updated to set the KB value to 0 if service pack is not
#  - installed and updated according to CR57. on 2012-03-27
#  - Enhaned the code to support Windows 8 32/64-bit service packs.
#  - Enhanced the code to support Windows Server 2012 64-bit Service packs.
#
#  Updated By: Sooraj KS <kssooraj@secpod.com> on 2012-05-09
#  - Added 64-bit processor architecture check.
#  - Enhanced the code to support Windows 7 64-bit Service packs.
#  - Enhanced the code to support Windows XP 64-bit Service packs.
#  - Enhanced the code to support Windows 2003 64-bit Service packs.
#  - Enhanced the code to support Windows Server 2008 R2 Service packs.
#
# Copyright:
# Copyright (C) 2000 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.10401";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 64 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-13 16:57:06 +0100 (Mi, 13. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-08-27 12:14:14 +0200 (Wed, 27 Aug 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("SMB Registry : Windows Service Pack version");
 
  tag_summary = 
"Detection of installed Windows Service Pack version.

The script logs in via SMB, and reads the registry key to retrieve
Windows Service Pack Version and sets KnowledgeBase.";

  desc = "

  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc); 
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_summary("Check for Service Pack on the remote host");
  script_copyright("This script is Copyright (C) 2000 Renaud Deraison");
  script_dependencies("smb_registry_access.nasl");
  script_mandatory_keys("SMB/registry_access");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");

access = "";
winVal = "";
winName = "";
csdVer = 0;
SP = "";

access = get_kb_item("SMB/registry_access");
if(!access){
  exit(0);
}

winVal = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                         item:"CurrentVersion");

if(winVal){
  set_kb_item(name:"SMB/WindowsVersion", value:winVal);
}

winName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"ProductName");

if(winName){
  set_kb_item(name:"SMB/WindowsName", value:winName);
}


csdVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                         item:"CSDVersion");

if(isnull(csdVer)){
  csdVer = "NO_Service_Pack";
}

## Check Processor Architecture
key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if(!registry_key_exists(key:key)) {
  exit(0);
}

arch = registry_get_sz(key:key, item:"PROCESSOR_ARCHITECTURE");
if("64" >< arch) {
  set_kb_item(name:"SMB/Windows/Arch", value:"x64");
}
else if("x86" >< arch) {
  set_kb_item(name:"SMB/Windows/Arch", value:"x86");
}

if(csdVer &&  "NO_Service_Pack" >!< csdVer)
{
  set_kb_item(name:"SMB/CSDVersion", value:csdVer);
  csdVer = eregmatch(pattern:"Service Pack [0-9]+", string:csdVer);
  if(!isnull(csdVer[0])){
    csdVer = csdVer[0];
  }

  ## Check For Windows
  if(winVal == "4.0"){
    set_kb_item(name:"SMB/WinNT4/ServicePack", value:csdVer);
  }

  ## Check for Windows 2000
  if((winVal == "5.0") && ("Microsoft Windows 2000" >< winName)){
    set_kb_item(name:"SMB/Win2K/ServicePack", value:csdVer);
  }

  ## Check Windows XP
  if((winVal == "5.1") && ("Microsoft Windows XP" >< winName)){
    set_kb_item(name:"SMB/WinXP/ServicePack", value:csdVer);
  }

  ## Check for Windows 2003
  if((winVal == "5.2") && ("Microsoft Windows Server 2003" >< winName) && ("x86" >< arch)){
    set_kb_item(name:"SMB/Win2003/ServicePack", value:csdVer);
  }

  ## Check Windows 2003 64 bit
  if((winVal == "5.2") && ("Microsoft Windows Server 2003" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win2003x64/ServicePack", value:csdVer);
  }

  ## Check for Windows Vista
  if((winVal == "6.0") && ("Windows Vista" ><winName)){
    set_kb_item(name:"SMB/WinVista/ServicePack", value:csdVer);
  }

  ## Check for Windows 7
  if((winVal == "6.1") && ("Windows 7" >< winName) && ("x86" >< arch)){
    set_kb_item(name:"SMB/Win7/ServicePack", value:csdVer);
  }

  ## Check Windows 7 64 bit
  if((winVal == "6.1") && ("Windows 7" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win7x64/ServicePack", value:csdVer);
  }

  ## Check for Windows Server 2008
  if((winVal == "6.0") && ("Windows Server (R) 2008" >< winName)){
    set_kb_item(name:"SMB/Win2008/ServicePack", value:csdVer);
  }

  ## Check Windows XP 64 bit
  if((winVal == "5.2") && ("Microsoft Windows XP" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/WinXPx64/ServicePack", value:csdVer);
  }

  ## Check for Windows Server 2008 R2
  if((winVal == "6.1") && ("Windows Server 2008 R2" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win2008R2/ServicePack", value:csdVer);
  }

  ## Check for Windows Server 2012
  if((winVal == "6.2") && ("Windows Server 2012" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win2012/ServicePack", value:csdVer);
  }

  ## Check for Windows 8
  if((winVal == "6.2") && ("Windows 8" >< winName) && ("32" >< arch)){
    set_kb_item(name:"SMB/Win8/ServicePack", value:csdVer);
  }

  ## windows Windows 8 64-bit code is not tested.
  ## Check for Windows 8 64-bit
  if((winVal == "6.2") && ("Windows 8" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win8x64/ServicePack", value:csdVer);
  }

  ## Check for Windows 8.1 32 bit
  if((winVal == "6.3") && ("Windows 8.1" >< winName) && ("x86" >< arch)){
    set_kb_item(name:"SMB/Win8.1/ServicePack", value:csdVer);
  }

  ## Check for Windows 8.1 64 bit
  if((winVal == "6.3") && ("Windows 8.1" >< winName) && ("64" >< arch)){
    set_kb_item(name:"SMB/Win8.1x64/ServicePack", value:csdVer);
  }
}

if(!isnull(winVal) && !isnull(csdVer) && "NO_Service_Pack" >!< csdVer)
{
  report = string("The ", winName, " ", winVal, " is installed with ",
                   csdVer, "\n");
   log_message(data:report, port:port);
}

else if(!isnull(winVal) && !isnull(csdVer) && "NO_Service_Pack" >< csdVer)
{
  SP = "0";
  set_kb_item(name:"SMB/Windows/ServicePack", value:SP);
  report = string("The ", winName, " ", winVal, " is installed with Service Pack ",
                   SP, "\n");
  log_message(data:report, port:port);
}
