###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# PHP Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2011-09-06
# Updated to detect old versions.
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 2012-09-25
# # Updated to detect RC versions.
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_summary = "Detection of installed version of PHP.

The script logs in via smb, searches for PHP in the registry and gets the
version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902435";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"detection", value:"registry version check");
  script_name("PHP Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
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
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm  PHP
key = "SOFTWARE\PHP\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get PHP version
phpVer = registry_get_sz(key:key, item:"version");
phpPath = registry_get_sz(key:key, item:"InstallDir");
if(!phpPath){
  phpPath = "Could not find the install location from registry";
}

## Get PHP version for old version
if(!phpVer)
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(!registry_key_exists(key:key)){
    exit(0);
  }

  foreach item (registry_enum_keys(key:key))
  {
    phpName = registry_get_sz(key:key + item, item:"DisplayName");

    if("PHP" >< phpName){
      phpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    }
  }
}

if(phpVer != NULL)
{
  if("RC" >< phpVer)
  {
    version = eregmatch(string:phpVer, pattern:"([0-9.]+)(RC([0-9]+))?");
    version[2] = tolower(version[2]);
    ver = version[1] + version[2];
    phpVer = version[1] + "." + version[2];
  }

  ## Set PHP version in KB
  set_kb_item(name:"PHP/Ver/win", value:phpVer);
  security_note(data:"PHP version " + phpVer + " was detected on the host");

  ## build cpe and store it as host_detail
  if(ver){
    cpe = build_cpe(value:ver, exp:"([0-9.]+)(RC([0-9]+))?", base:"cpe:/a:php:php:");
  }
  else{
   cpe = build_cpe(value:phpVer, exp:"^([0-9.]+)", base:"cpe:/a:php:php:");
  }

  if(isnull(cpe)){
    cpe = "cpe:/a:php:php";
  }

  register_product(cpe:cpe, location:phpPath, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app:"PHP",
                                           version:phpVer, install:phpPath,
                                           cpe:cpe, concluded: phpVer));
}
