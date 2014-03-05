###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_gom_player_detect_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# GOM Media Player Version Detection (Windows)
#
# Authors:
# Madhuri D <madhurid@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_summary = "Detection of installed version of GOM Media Player.

The script logs in via smb, searches for GOM Media Player in the
registry and gets the installed path from 'ProgramPath' string in registry
and grep the version from .exe file";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903001";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-21 15:27:17 +0530 (Wed, 21 Mar 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("GOM Media Player Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Set KB for the version of GOM Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialisation
key = "";
cpe = "";
path = "";
gomVer = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check appln is installed
key = "SOFTWARE\GRETECH\GomPlayer";
if(!(registry_key_exists(key:key))){
  exit(0);
}

## Get the installed Path
path = registry_get_sz(key:key, item:"ProgramPath");
if(!path){
  exit(0);
}

gomVer = fetch_file_version(sysPath:path, file_name:"");
if(gomVer)
{
  ## Setting the Version
  set_kb_item(name:"GOM/Player/Ver/Win", value:gomVer);

  cpe = build_cpe(value:gomVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:gomlab:gom_media_player:");
  if(!isnull(cpe))
    register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

  log_message(data:'Detected GOM Player version: ' + gomVer +
    '\nLocation: ' + path +
    '\nCPE: '+ cpe +
    '\n\nConcluded from version identification result:\n' + 'GOM Player '+ gomVer);
}
