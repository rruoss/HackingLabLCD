###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Adobe Shockwave Player Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Rachana Shetty <srachana@secpod.com> on 2011-08-24
#  - Updated to the to get proper System32 path
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-19
# According to cr57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900581";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Adobe Shockwave Player Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Adobe Shockwave Player on Windows.

The script logs in via smb, searches for Adobe Shockwave Player in the
registry, gets the version and set it in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check for the presence of Adobe Shockwave Player on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

## Variable Initialization
swplayerName = "";
unintPath = "";
exePath = "";
swVer = "";

## Check for Adobe
if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  if(!registry_key_exists(key:"SOFTWARE\Macromedia")) exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for Shockwave
  swplayerName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Shockwave" >< swplayerName)
  {
    ## Get the installed Path
    unintPath = registry_get_sz(key:key + item, item:"UninstallString");
    break;
  }
}

if(unintPath != NULL)
{
  swPath = smb_get_systemroot();
  if(swPath == NULL){
    exit(0);
  }

  if("Adobe" >< unintPath){
    path = "Adobe";
  }
  else if("Macromed" >< unintPath){
    path = "Macromed";
  }

  exePath = swPath + "\System32\" + path + "\Shockwave";

  ## Get the version
  swVer = fetch_file_version(sysPath: exePath, file_name: "swinit.exe");
  if(!swVer)
  {
    for(i=8; i<=12; i++)
    {
      swVer = fetch_file_version(sysPath: exePath + " " + i, file_name: "swinit.exe");
      if(swVer != NULL)
      {
        exePath = exePath + " " + i;
        break;
      }
    }
  }

  if(swVer)
  {
    set_kb_item(name:"Adobe/ShockwavePlayer/Ver", value:swVer);

    ## Build CPE
    cpe = build_cpe(value: swVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
    if(isnull(cpe))
      cpe = "cpe:/a:adobe:shockwave_player";

    register_product(cpe: cpe, location: exePath, nvt: SCRIPT_OID);

    log_message(data: build_detection_report(app: swplayerName,
                                             version: swVer,
                                             install: exePath,
                                             cpe: cpe,
                                             concluded: swVer));
  }
}
