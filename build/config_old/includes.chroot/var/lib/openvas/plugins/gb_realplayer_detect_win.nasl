###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# RealPlayer Application Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-12-28
# Updated to detect Older version and according to CR-57
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of RealNetworks
RealPlayer.

The script logs in via smb, searches for RealPlayer in the registry and
gets the path for 'realplayer.exe' file in registry and version from
realplayer.exe file";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800508";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_name("RealPlayer Application Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of RealPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
rpFile = "";
oldPath = "";
rpVer = "";
cpe = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get the RealPlay.exe Path from Registry
foreach file (make_list("\RealPlay.exe", "\realplay.exe"))
{
  ## Get the RealPlay.exe Path from Registry
  rpFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths" + file, item:"Path");
  if(!rpFile)
    continue;
}

if(!rpFile)
  exit(0);

if(file =~ "realplay.exe")
{
   oldPath = eregmatch(pattern:"(.*);", string:rpFile);
   if(oldPath && oldPath[0])
      rpFile =  oldPath[1];
}


## Get realplay.exe Version
rpVer = fetch_file_version(sysPath: rpFile, file_name:"realplay.exe");
if(isnull(rpVer))
   exit(0);

## Check if it RealPlayer Enterprise
if("RealPlayer Enterprise" >< rpFile)
{
  set_kb_item(name:"RealPlayer-Enterprise/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:" +
                               rpVer + "::enterprise");
}
else
{
  set_kb_item(name:"RealPlayer/Win/Ver", value:rpVer);
  cpe = build_cpe(value:rpVer, exp:"^([0-9.]+)", base:"cpe:/a:realnetworks:realplayer:");
}

if(isnull(cpe))
  cpe = 'cpe:/a:realnetworks:realplayer:';

register_product(cpe:cpe, location:rpFile, nvt:SCRIPT_OID);

log_message(data: build_detection_report(app:"Detected RealNetworks RealPlayer" ,
                                         version: rpVer, install: rpFile, cpe:cpe, concluded:rpVer));
