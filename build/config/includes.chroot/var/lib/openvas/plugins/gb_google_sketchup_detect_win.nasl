##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_sketchup_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# Google SketchUp Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-10-09
# Updated to detect for version higher version
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Google SketchUp.

The script logs in via smb, searches for Google SketchUp in the registry
and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800434";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_name("Google SketchUp Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Google SketchUp");
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

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Google")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  gsName = registry_get_sz(key:key + item, item:"DisplayName");
  if(gsName =~ "(Google )?SketchUp")
  {
    path = registry_get_sz(key:key + item , item:"InstallLocation");

    if(path)
    {
      gsVer = fetch_file_version(sysPath:path, file_name:"SketchUp.exe");
      if(gsVer != NULL)
      {
        set_kb_item(name:"Google/SketchUp/Win/Ver", value:gsVer);

        ## Build CPE
        cpe = build_cpe(value:gsVer, exp:"^([0-9.]+)", base:"cpe:/a:google:sketchup:");
        if(isnull(cpe))
          cpe = 'cpe:/a:google:sketchup';

        register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

        log_message(data: build_detection_report(app: gsName, version: gsVer,
                                                 install: path, cpe:cpe, concluded:gsVer));

        exit(0);
      }
    }
  }
}
