##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cuteftp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# CuteFTP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script finds the installed CuteFTP version and saves the
  result in KB item.";

if(description)
{
  script_id(800947);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("CuteFTP Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of CuteFTP in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800947";
SCRIPT_DESC = "CuteFTP Version Detection";


## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!(registry_key_exists(key:"SOFTWARE\GlobalSCAPE Inc.")||
     registry_key_exists(key:"SOFTWARE\GlobalSCAPE"))){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
foreach item (registry_enum_keys(key:key))
{
  cName = registry_get_sz(key:key + item, item:"DisplayName");
  cftpName = eregmatch(pattern:"CuteFTP [0-9.?]+ ([a-zA-Z]+)",string:cName);
  if(cftpName[1] != NULL)
  {
    cPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(cPath == NULL){
      exit(0);
    }

    cPath = cPath - ",-0";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:cPath);
    file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:cPath);
    cftpVer = GetVer(share:share, file:file);
    if(!isnull(cftpVer))
    {
      set_kb_item(name:"CuteFTP/"+string(cftpName[1])+"/Ver", value:cftpVer); 
      security_note(data:"Cute FTP version " + cftpVer + " running at location "
                         + cPath + " was detected on the host");

      ## build cpe and store it as host_detail
      # Home
      register_cpe(tmpVers:cftpVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:globalscape:cuteftp:");
      # Lite
      register_cpe(tmpVers:cftpVer, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:globalscape:cuteftp:");
      # Pro
      register_cpe(tmpVers:cftpVer, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:globalscape:cuteftp:");
    }
  }
}
