###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_vs_team_foundation_server_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Visual Studio Team Foundation Server Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Microsoft Visual Studio Team Foundation Server.

The script logs in via smb, searches for Microsoft Visual Studio Team
Foundation Server in the registry and gets the version from 'Version' string
in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802961";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-12 11:27:31 +0530 (Wed, 12 Sep 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_name("Microsoft Visual Studio Team Foundation Server Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Microsoft Visual Studio Team Foundation Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
tfName = "";
cpe = "";
tfVer = "";
insPath = "";
key = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm application is installed
if(!registry_key_exists(key:"SOFTWARE\Microsoft\TeamFoundationServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Checking for DisplayName
  tfName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft Team Foundation Server" >< tfName )
  {
    tfNum = eregmatch(pattern:"([0-9.]+)", string:tfName);

    ## Get the version
    tfVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(tfVer)
    {
      ## Get the installation path
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath){
        insPath = "Could not find the install location from registry";
      }

      ## Set the KB item
      set_kb_item(name:"MS/VS/Team/Foundation/Server/Ver", value:tfVer);
      set_kb_item(name:"MS/VS/Team/Foundation/Server/Path", value:insPath);

      ## build cpe and store it as host_detail
      if(tfNum[0])
      {
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:visual_studio_team_foundation_server:"
                                 + tfNum[0]);
      }
      else{
        cpe = build_cpe(value:tfVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:visual_studio_team_foundation_server:");
      }

      if(!cpe){
        cpe = "cpe:/a:microsoft:visual_studio_team_foundation_server";
      }

      register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:"MS VS Team Foundation",
                                              version:tfVer, install:insPath, cpe:cpe,
                                              concluded: tfVer));
      exit(0);
    }
  }
}
