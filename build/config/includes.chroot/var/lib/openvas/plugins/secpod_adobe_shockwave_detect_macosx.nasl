###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Adobe Shockwave Player Version Detection (MacOSX)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.902619";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Adobe Shockwave Player Version Detection (MacOSX)");

  tag_summary =
"Detection of installed version of Adobe Shockwave Player on Mac OS X.

The script logs in via ssh, and searches for adobe products '.app' folder
and queries the related 'info.plist' file for string
'CFBundleShortVersionString' via command line option 'defaults read'.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check for the presence of Adobe Shockwave Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
shockVer = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of Adobe Shockwave
shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
          "Application\\ Support/Adobe/Shockwave/DirectorShockwave.bundle/"+
          "Contents/Info CFBundleShortVersionString"));

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\\ Support/Adobe/Shockwave\\ "+ i +
               "/DirectorShockwave.bundle/Contents/Info " +
               "CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

if(isnull(shockVer) || "does not exist" >< shockVer)
{
  for(i=8; i<=12; i++)
  {
    shockVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/" +
               "Application\\ Support/Macromedia/Shockwave\\ "+ i +
               "/Shockwave.bundle/Contents/Info CFBundleShortVersionString"));

    if("does not exist" >!< shockVer){
       break;
    }
  }
}

## Close Socket
close(sock);

## Exit if version not found
if(isnull(shockVer) || "does not exist" >< shockVer){
  exit(0);
}

shockVer = ereg_replace(pattern:"r", string:shockVer, replace: ".");

## Set the version in KB
set_kb_item(name: "Adobe/Shockwave/MacOSX/Version", value:shockVer);

## Build CPE
cpe = build_cpe(value: shockVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
if(isnull(cpe))
  cpe = "cpe:/a:adobe:shockwave_player";

register_product(cpe: cpe, location: "/Library/", nvt: SCRIPT_OID);

log_message(data: build_detection_report(app: "Adobe Shockwave Player",
                                         version: shockVer,
                                         install: "/Applications/",
                                         cpe: cpe,
                                         concluded: shockVer));
