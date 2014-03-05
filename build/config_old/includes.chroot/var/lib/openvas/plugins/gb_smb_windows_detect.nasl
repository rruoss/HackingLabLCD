###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smb_windows_detect.nasl 42 2013-11-04 19:41:32Z jan $
#
# SMB Windows Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of installed Windows version";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103621";
desc = "
 Summary:
 " + tag_summary;

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-08-27 12:14:14 +0200 (Wed, 27 Aug 2008)");
 script_name("SMB Windows Detection");
 script_description(desc);
 script_category(ACT_GATHER_INFO);
 script_family("Windows");
 script_summary("Check for Service Pack on the remote host");
 script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");
include("cpe.inc");

winVal  = get_kb_item("SMB/WindowsVersion");

if(!winVal)exit(0);

winName = get_kb_item("SMB/WindowsName");
csdVer  = get_kb_item("SMB/CSDVersion");
arch    = get_kb_item("SMB/Windows/Arch");

if(isnull(csdVer)){
  csdVer = "";
} else {

  csdVer = eregmatch(pattern:"Service Pack [0-9]+", string:csdVer);
  if(!isnull(csdVer[0])){
    csdVer = csdVer[0];
  }

}  

function register_win_version() {
  local_var cpe_base, win_vers, servpack, cpe;

  cpe_base = _FCT_ANON_ARGS[0];
  win_vers = _FCT_ANON_ARGS[1];
  servpack = _FCT_ANON_ARGS[2];

  servpack = ereg_replace(string:servpack, pattern:"Service Pack ", replace:"sp", icase:1);

  if (!isnull(servpack) && strlen(servpack) > 0) {

    if (isnull(win_vers))
      win_vers = "";

    cpe = string(cpe_base, ":", win_vers, ":", servpack);
  } else if (!isnull(win_vers) && strlen(win_vers) > 0) {
    cpe = string(cpe_base, ":", win_vers);
  } else {
    cpe = cpe_base;
  }
  register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID, desc:desc);
}

## Check For Windows
if(winVal == "4.0"){
  register_win_version("cpe:/o:microsoft:windows_nt", "4.0", csdVer);
}

## Check for Windows 2000
if((winVal == "5.0") && ("Microsoft Windows 2000" >< winName)){
  register_win_version("cpe:/o:microsoft:windows_2000", "", csdVer);
}

## Check Windows XP
if((winVal == "5.1") && ("Microsoft Windows XP" >< winName)){
  register_win_version("cpe:/o:microsoft:windows_xp", "", csdVer);
}

## Check for Windows 2003
if((winVal == "5.2") && ("Microsoft Windows Server 2003" >< winName) && ("x86" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_server_2003", "", csdVer);
}

## Check Windows 2003 64 bit
if((winVal == "5.2") && ("Microsoft Windows Server 2003" >< winName) && ("64" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_server_2003", "", csdVer);
}

## Check for Windows Vista
if((winVal == "6.0") && ("Windows Vista" ><winName)){
  register_win_version("cpe:/o:microsoft:windows_vista", "", csdVer);
}

## Check for Windows 7
if((winVal == "6.1") && ("Windows 7" >< winName) && ("x86" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_7", "", csdVer);
}

## Check Windows 7 64 bit
if((winVal == "6.1") && ("Windows 7" >< winName) && ("64" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_7", "", csdVer);
}

## Check for Windows Server 2008
if((winVal == "6.0") && ("Windows Server (R) 2008" >< winName)){
  register_win_version("cpe:/o:microsoft:windows_server_2008", "", csdVer);
}

## Check Windows XP 64 bit
if((winVal == "5.2") && ("Microsoft Windows XP" >< winName) && ("64" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_xp", "", csdVer);
}

## Check for Windows Server 2008 R2
if((winVal == "6.1") && ("Windows Server 2008 R2" >< winName) && ("64" >< arch)){
  register_win_version("cpe:/o:microsoft:windows_server_2008:r2", "", csdVer);
}

## Check for Windows Server 2012
if((winVal == "6.2") && ("Windows Server 2012" >< winName) && ("64" >< arch)){
    register_win_version("cpe:/o:microsoft:windows_server_2012", "", csdVer);
}

## Check for Windows 8
if((winVal == "6.2") && ("Windows 8" >< winName)){
      register_win_version("cpe:/o:microsoft:windows_8", "", csdVer);
}

exit(0);
