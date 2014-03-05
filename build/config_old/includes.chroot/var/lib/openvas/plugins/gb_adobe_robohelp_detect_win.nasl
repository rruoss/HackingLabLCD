###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_robohelp_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Adobe RoboHelp Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803770";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-17 15:40:00 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Adobe RoboHelp Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Adobe RoboHelp on Windows.

The script logs in via smb, searches for Adobe RoboHelp in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check the presence of Adobe RoboHelp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


##
## code starts here
##

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable initialization
arhName = "";
arhInsPath = "";
arhVer = "";

## Confirm the Adobe RoboHelp installation
if(!registry_key_exists(key:"SOFTWARE\Adobe\RoboHelp")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
foreach item (registry_enum_keys(key:key))
{
  arhName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm for Adobe RoboHelp
  if("Adobe RoboHelp" >< arhName)
  {
    ## Get the install location
    arhInsPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(arhInsPath){
      arhInsPath = arhInsPath - "\ARPRobohelp.ico";
    }
    else {
      arhInsPath = "Could not find the install location from registry";
    }

    ## Get the Adobe RoboHelp version
    arhVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(arhVer)
    {
      ## Set the KB
      set_kb_item(name:"Adobe/RoboHelp/Win/Ver", value: arhVer);
      set_kb_item(name:"Adobe/RoboHelp/Win/InsallPath", value: arhInsPath);

      ## build cpe
      cpe = build_cpe(value: arhVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:robohelp:");
      if(isnull(cpe))
        cpe = 'cpe:/a:adobe:robohelp';

      ## Register the product
      register_product(cpe:cpe, location:arhInsPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: arhName,
                                               version: arhVer,
                                               install: arhInsPath,
                                               cpe: cpe,
                                               concluded: arhVer));
    }
  }
}