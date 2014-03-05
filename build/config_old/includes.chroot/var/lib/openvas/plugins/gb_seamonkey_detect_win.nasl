###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_detect_win.nasl 42 2013-11-04 19:41:32Z jan $
#
# Mozilla Seamonkey Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Upgrade to detect the latest version
# - By Sharath S <sharaths@secpod.com> On 2009-11-02 #5567
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800016";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Mozilla SeaMonkey Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Mozilla SeaMonkey on Windows.

The script logs in via smb, searches for Mozilla SeaMonkey in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set Version of Mozilla SeaMonkey in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
appName = "";
insPath = "";
seaVer = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

# Check for SeaMonkey version through Registry entry
seaVer = registry_get_sz(key:"SOFTWARE\mozilla.org\SeaMonkey",
                         item:"CurrentVersion");
if(!seaVer){
  seaVer = registry_get_sz(key:"SOFTWARE\Mozilla\SeaMonkey",
                           item:"CurrentVersion");
}

seaVer = eregmatch(pattern:"[0-9.]+", string:seaVer);
seaVer = seaVer[0];

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm for SeaMonkey
  if("SeaMonkey" >< appName)
  {
    if(!seaVer)
      seaVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    insPath = registry_get_sz(key:key + item, item:"InstallLocation");

    break;
  }
  appName = "";
}

if(seaVer)
{

  if(!appName && !insPath) {
    if(seaVer <= 0)exit(0);
  }  

  if(!appName) appName = "Mozilla SeaMonkey";

  if(!insPath)
    insPath = "Could not find the install location";

  set_kb_item(name:"Seamonkey/Win/Ver", value: seaVer);

  ## build cpe
  cpe = build_cpe(value: seaVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mozilla:seamonkey:");
  if(isnull(cpe))
    cpe = 'cpe:/a:mozilla:seamonkey';

  register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: appName,
                                           version: seaVer,
                                           install: insPath,
                                           cpe: cpe,
                                           concluded: seaVer));
}
