###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Wireshark Version Detection (MacOSX)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-27
# According to cr57 and new style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802762";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-04-24 14:25:07 +0530 (Tue, 24 Apr 2012)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Wireshark Version Detection (MacOSX)");

  tag_summary =
"Detection of installed version of Wireshark on Mac OS X.

The script logs in via ssh, searches for folder 'Wireshark.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Wireshark on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
sharkVer = "";
sock = "";
cpe  = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock) {
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of Wireshark
sharkVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                "Wireshark.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(sharkVer) || "does not exist" >< sharkVer){
  exit(0);
}

## Set KB
set_kb_item(name: "Wireshark/MacOSX/Version", value:sharkVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:sharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
if(isnull(cpe))
  cpe = 'cpe:/a:wireshark:wireshark';

register_product(cpe:cpe, location:'/Applications/Wireshark.app', nvt:SCRIPT_OID);

log_message(data: build_detection_report(app: "Wireshark", version: sharkVer,
                                         install: "/Applications/Wireshark.app",
                                         cpe: cpe,
                                         concluded: sharkVer));
