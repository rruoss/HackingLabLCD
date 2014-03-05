###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_livecycle_designer_detect_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe LiveCycle Designer Version Detection (Windows)
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
tag_summary = "Detection of installed version of Adobe LiveCycle Designer.

The script logs in via smb, searches for Adobe LiveCycle Designer in the registry
and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802959";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-11 16:00:34 +0530 (Tue, 11 Sep 2012)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Adobe LiveCycle Designer Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Adobe LiveCycle Designer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cpe = "";
designVer = "";
designPath = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm application installation
if(!registry_key_exists(key:"SOFTWARE\Adobe\Designer")){
    exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  designName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Adobe LiveCycle Designer" >< designName)
  {
    esName = eregmatch(pattern:"ES([0-9.]+)", string:designName);
    designPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(designPath)
    {
      designVer = fetch_file_version(sysPath:designPath, file_name:"FormDesigner.exe");
      if(designVer)
      {
        set_kb_item(name:"Adobe/LiveCycle/Designer", value:designVer);

        ## build cpe and store it as host_detail
        if(esName[0])
        {
          esName[0] = tolower(esName[0]);
          cpe = build_cpe(value:designVer, exp:"^([0-9.]+)",
                          base:"cpe:/a:adobe:livecycle_designer_" + esName[0] + ":");
        }
        else{
          cpe = build_cpe(value:designVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:livecycle_designer:");
        }

        if(isnull(cpe))
          cpe = "cpe:/a:adobe:livecycle_designer";

        register_product(cpe:cpe, location:designPath, nvt:SCRIPT_OID);

        log_message(data: build_detection_report(app:"Adobe LiveCycle Designer",
                                                 version:designVer, install:designPath,
                                                 cpe:cpe, concluded: designVer));
      }
    }
  }
}
