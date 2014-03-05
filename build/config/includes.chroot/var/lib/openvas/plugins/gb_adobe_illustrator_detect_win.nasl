###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_illustrator_detect_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Illustrator Detection (Windows)
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
tag_summary = "Detection of installed version of Adobe Illustrator.

The script logs in via smb, searches for Adobe Illustrator in the
registry and gets the version from 'Version' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802789";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-16 19:02:06 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Illustrator Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Adobe Illustrator on Windows");
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
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
appPath = "";
ilsName = "";
ver = "";
ilsVer = "";
cpe = NULL;
ilsPath = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm appln is installed
appkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Illustrator.exe";
if(!registry_key_exists(key:appkey)) {
  exit(0);
}

## Get the installed path
appPath = registry_get_sz(key:appkey, item:"Path");
if(appPath){
  appPath = appPath - "\Support Files\Contents\Windows";
}
else {
  appPath = "Could not find the install location from registry";
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ilsName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Adobe Illustrator CS" >< ilsName)
  {
    ilsVer = eregmatch(pattern:"CS([0-9.]+)", string:ilsName);

    if(ilsVer[0] && ilsVer[1])
    {
      ver = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(ver != NULL)
      {
        tmp_version = ilsVer[0] + " " + ver;

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:adobe:illustrator_cs"
                                     + ilsVer[1] + ":");
      }
    }
  }

  ilsPath = registry_get_sz(key:key + item, item:"InstallLocation");
  if(ilsPath && "Adobe" >< ilsPath && "Illustrator" >< ilsPath)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver){
      tmp_version = ver;
    }

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:illustrator:");
  }

  if(tmp_version)
  {
    set_kb_item(name:"Adobe/Illustrator/Win/Ver", value:tmp_version);

    if(!isnull(cpe))
      register_product(cpe:cpe, location:appPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:"Adobe Illustrator",
                                           version:tmp_version,
                                           install: appPath,
                                           cpe:cpe,
                                           concluded: tmp_version));
    exit(0);
  }
}
