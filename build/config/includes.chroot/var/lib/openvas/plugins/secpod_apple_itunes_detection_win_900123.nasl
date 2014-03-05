###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_itunes_detection_win_900123.nasl 42 2013-11-04 19:41:32Z jan $
#
# Apple iTunes Version Detection (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900123";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Apple iTunes Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Apple iTunes on Windows.

The script logs in via smb, searches for Apple iTunes in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Apple iTunes on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
ituneName = "";
insPath = "";
ituneVer = "";
cpe = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ituneName = registry_get_sz(key:key + item, item:"DisplayName");
  if("iTunes" >< ituneName)
  {
    insPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insPath){
      insPath = "Could not find the install Location from regestry";
    }

    ituneVer = registry_get_sz(key: key + item, item:"DisplayVersion");
    if(ituneVer)
    {
      set_kb_item(name:"iTunes/Win/Ver", value:ituneVer);

      ## Build cpe
      cpe = build_cpe(value:ituneVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:itunes:");
      if(isnull(cpe))
        cpe = 'cpe:/a:apple:itunes';

      register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: ituneName,
                                               version: ituneVer,
                                               install: insPath,
                                               cpe: cpe,
                                               concluded: ituneVer));
    }
  }
}
