##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_silverlight_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft Silverlight Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated: Veerendra GG <veerendragg@secpod.com> on 2013-08-09
# According to CR57 and New Style script_tags.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801934";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Microsoft Silverlight Version Detection");

  tag_summary =
"Detection of installed version of Microsoft Silverlight on Windows.

The script logs in via smb, searches for Silverlight in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Microsoft Silverlight on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
cpe = "";
un_key = "";
msl_key = "";
ins_loc = "";
msl_ver = "";

## Check Silverlight is present or not
msl_key = "SOFTWARE\Microsoft\Silverlight";
if(!msl_key){
  exit(0);
}

un_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:un_key)){
    exit(0);
}

msl_ver = registry_get_sz(key:msl_key, item:"Version");

## Need to iterate over Uninstall path to get installed path and display name.
foreach item (registry_enum_keys(key:un_key))
{
  ## Get application name
  app_name = registry_get_sz(key:un_key + item, item:"DisplayName");
  if("Microsoft Silverlight" >!< app_name){
    continue;
  }

  ## Get version if not available in previous path
  if(!msl_ver || msl_ver == "0"){
    msl_ver = registry_get_sz(key:un_key + item, item:"DisplayVersion");
  }

  ## Get installed location
  ins_loc = registry_get_sz(key:un_key + item, item:"InstallLocation");
  if(!ins_loc){
    ins_loc = "Unable to find the install location from registry.";
  }

  break;
}

## Ths might be needed for older NVTs
if(msl_ver){
  ## Set KB for Microsoft Silverlight
  set_kb_item(name:"Microsoft/Silverlight", value:msl_ver);

}

if(msl_ver && "Microsoft Silverlight" >< app_name)
{
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:msl_ver, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:silverlight:");
  if(isnull(cpe))
    cpe = "cpe:/a:microsoft:silverlight";

  ## Register product
  register_product(cpe:cpe, location:ins_loc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app:app_name,
                                           version:msl_ver,
                                           install:ins_loc,
                                           cpe:cpe,
                                           concluded:msl_ver));
}
