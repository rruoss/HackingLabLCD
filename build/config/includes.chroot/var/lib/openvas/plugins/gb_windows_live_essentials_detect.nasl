###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_windows_live_essentials_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Windows Live Essentials Version Detection
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Windows Live Essentials.

The script logs in via smb, searches for Windows Live Essentials in the
registry and gets the version from 'wlarp.exe' file from installation";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803603";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-15 14:11:55 +0530 (Wed, 15 May 2013)");
  script_name("Windows Live Essentials Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Windows Live Essentials");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");


key = "";
path = "";
version = "";
cpe = "";

## Confirm target is Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinLiveSuite\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get version and location of Windows Live Essentials
name = registry_get_sz(key:key, item:"DisplayName");
if("Windows Live Essentials" >< name)
{
   version = registry_get_sz(key:key, item:"DisplayVersion");
   if(version)
   {
     path = registry_get_sz(key:key, item:"InstallLocation");
     if(path)
     {
       ## Set the KB item
       set_kb_item(name:"Windows/Essentials/Ver", value:version);
       set_kb_item(name:"Windows/Essentials/Loc", value:path);
       cpe = build_cpe(value:version, exp:"^([0-9.]+)",
                         base:"cpe:/a:microsoft:windows_essentials:");
       if(!cpe){
         cpe = "cpe:/a:microsoft:windows_essentials";
       }

       register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

       log_message(data: build_detection_report(app: name, version:version,
                                               install:path, cpe:cpe,
                                               concluded: version));
    }
  }
}
