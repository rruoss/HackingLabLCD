###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_fast_search_server_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft FAST Search Server Detection
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
tag_summary = "Detection of installed version of Microsoft FAST Search Server.

The script logs in via smb, searches for Microsoft FAST Search Server in the
registry and gets the version from 'Version' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802980";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-10-10 10:36:03 +0530 (Wed, 10 Oct 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_name("Microsoft FAST Search Server Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Microsoft FAST Search Server");
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
fsName = "";
cpe = "";
fsVer = "";
key = "";
fsKey = "";
insPath = "";
item = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm application installation
fsKey = "SOFTWARE\Microsoft\FAST Search Server";
if(!registry_key_exists(key:fsKey)){
  exit(0);
}

## Get the installation path
fsKey = fsKey + "\Setup";
insPath = registry_get_sz(key:fsKey, item:"Path");
if(!insPath){
  insPath = "Could not find the install location from registry";
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for the DisplayName
  fsName = registry_get_sz(key:key + item, item:"DisplayName");
  if(!fsName){
    continue;
  }

  if("Microsoft FAST Search Server" >< fsName )
  {
    ver = eregmatch(string:fsName, pattern:"([0-9]+)");

    ## Get the version
    fsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(fsVer)
    {
      ## Set the KB item
      set_kb_item(name:"MS/SharePoint/Server/Ver", value:fsVer);
      set_kb_item(name:"MS/SharePoint/Install/Path", value:insPath);

      if(ver[0])
      {
        cpe = build_cpe(value:fsVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:fast_search_server_for_sharepoint:" + ver[0]);
      }
      else
      {
        cpe = build_cpe(value:fsVer, exp:"^([0-9.]+)",
                           base:"cpe:/a:microsoft:fast_search_server_for_sharepoint:");
      }

      if(!cpe){
        cpe = "cpe:/a:microsoft:fast_search_server_for_sharepoint";
      }

      register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:"MS Fast Search Server version",
                                              version:fsVer, install:insPath, cpe:cpe,
                                              concluded: fsVer));
      exit(0);
    }
  }
}
