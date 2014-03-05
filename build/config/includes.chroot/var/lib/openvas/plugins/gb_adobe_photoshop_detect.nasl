###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Adobe Photoshop Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-05-24
#  - To detect recent version of Adobe Photoshop
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Adobe Photoshop.

The script logs in via smb, searches for Adobe Photoshop in the
registry and gets the version from 'Version' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801224";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_name("Adobe Photoshop Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of Adobe Photoshop in KB for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
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
include("version_func.inc");

## Variable Initialization
item = "";
name = "";
ver = "";
path = "";
tmp_version = "";
cpe = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

appkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Photoshop.exe";
if(!registry_key_exists(key:appkey)) {
  exit(0);
}

## Get the installed path
appPath = registry_get_sz(key:appkey, item:"Path");
if(appPath)
{
  photoVer = fetch_file_version(sysPath:appPath, file_name:"Photoshop.exe");
  if(!photoVer){
    exit(0);
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");

  if("Photoshop" >!< name){
    continue;
  }

  path = registry_get_sz(key:key + item, item:"InstallLocation");
  if(!path){
    path = "";
  }

  if("Adobe Photoshop CS" >< name)
  {
    ver = eregmatch(pattern:"CS([0-9.]+)", string:name);
    if(ver[0])
    {
      tmp_version = ver[0] + " " + photoVer;

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:photoVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:photoshop_cs"
                                     + ver[1] + ":");
    }
  }

  else if("Adobe Photoshop" >< name)
  {
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:photoVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:photoshop:");
    tmp_version = photoVer;
  }

  if(isnull(cpe)){
    cpe = "cpe:/a:adobe:photoshop";
  }

  ## Set KB
  set_kb_item(name:"Adobe/Photoshop/Ver", value:tmp_version);

  register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app:"Adobe Photoshop",
                                           version:tmp_version,
                                           install: path,
                                           cpe:cpe,
                                           concluded: tmp_version));
    exit(0);
}
