###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_silverlight_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft Silverlight Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated: Veerendra GG <veerendragg@secpod.com> on 2013-08-09
# According to New Style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802854";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-05-14 14:56:10 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Silverlight Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Microsoft Silverlight on Mac OS X.

The script logs in via ssh, and searches for Microsoft Silverlight
'Silverlight.plugin' folder and queries the related 'Info.plist' file
for string 'CFBundleShortVersionString' via command line option
'defaults read'.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Microsoft Silverlight on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success", "ssh/login/osx_name");
  exit(0);
}


include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Get the version of Microsoft Silverlight
slightVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Library/Internet\\ Plug-Ins/"+
                          "Silverlight.plugin/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(slightVer) || "does not exist" >< slightVer){
  exit(0);
}

## build cpe and store it as host_detail
cpe = build_cpe(value: slightVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:silverlight:" +
                   slightVer + "::mac");
if(!isnull(cpe))
  register_product(cpe:cpe, location:'/Library/Internet\\ Plug-Ins/Silverlight.plugin', nvt:SCRIPT_OID);
else
  cpe = "Failed";

## Set the version in KB
set_kb_item(name: "MS/Silverlight/MacOSX/Ver", value: slightVer);
log_message(data: build_detection_report(app:"Microsoft Silverlight on Mac OS X",
                                         version: slightVer,
                                         install: '/Library/Internet Plug-Ins/Silverlight.plugin',
                                         cpe: cpe,
                                         concluded: slightVer));
