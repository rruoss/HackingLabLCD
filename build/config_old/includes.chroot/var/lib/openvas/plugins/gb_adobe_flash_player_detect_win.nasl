###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_detect_win.nasl 42 2013-11-04 19:41:32Z jan $
#
# Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-18
# According to CR57 and new style script_tags.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800029";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Win)");

  tag_summary =
"Detection of installed version of Adobe Flash Player/Flash CS/AIR/Flex
on Windows.

The script logs in via smb, searches for Adobe Products in the registry
and gets the version from 'DisplayVersion' string in registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set KB for the version of Adobe Flash Player/Flash CS/AIR/Flex on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

## variable Initialization
adobeName = "";
playerFlag = 0;
flexFlag = 0;
airFlag = 0;
csFlag = 0;

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  if(!insloc)
    insloc = "Unable to find the install location";

  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  adobeName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm for Adobe AIR
  if("Adobe AIR" >< adobeName && airFlag == 0)
  {
    airVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(airVer != NULL)
    {
      set_kb_item(name:"Adobe/Air/Win/Ver", value:airVer);

      ## Build CPE
      cpe = build_cpe(value:airVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:adobe_air:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:adobe_air";

      ## Register Product and Build Report
      build_report(app: adobeName, ver: airVer, cpe: cpe, insloc: insPath);

      airFlag = 1;
    }
  }

  ## Confirm for Adobe Flash CS
  else if("Adobe Flash CS" >< adobeName && csFlag == 0)
  {
    fcsVer = eregmatch(pattern:"Flash (CS[0-9])", string:adobeName);
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(fcsVer[1] != NULL)
    {
      set_kb_item(name:"Adobe/FlashCS/Win/Ver", value:fcsVer[1]);

      ## Build CPE
      cpe = build_cpe(value:fcsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_cs:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:flash_cs";

      ## Register Product and Build Report
      build_report(app: adobeName, ver: fcsVer[1], cpe: cpe, insloc: insPath);

      csFlag = 1;
    }
  }

  ## Confirm for Adobe Flash Player
  else if("Adobe Flash Player" >< adobeName && playerFlag == 0)
  {
    playerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(playerVer != NULL)
    {
      set_kb_item(name:"AdobeFlashPlayer/Win/Ver", value:playerVer);

      ## Build CPE
      cpe = build_cpe(value:playerVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:flash_player";

      ## Register Product and Build Report
      build_report(app: adobeName, ver: playerVer, cpe: cpe, insloc: insPath);

      playerFlag = 1;
    }
  }

  ## Confirm for Adobe Flex
  else if("Adobe Flex" >< adobeName && flexFlag == 0)
  {
    flexVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(flexVer != NULL)
    {
      set_kb_item(name:"Adobe/Flex/Win/Ver", value:flexVer);

      ## Build CPE
      cpe = build_cpe(value:flexVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flex:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:flex";

      ## Register Product and Build Report
      build_report(app: adobeName, ver: flexVer, cpe: cpe, insloc: insPath);

      flexFlag = 1;
    }
  }
}
