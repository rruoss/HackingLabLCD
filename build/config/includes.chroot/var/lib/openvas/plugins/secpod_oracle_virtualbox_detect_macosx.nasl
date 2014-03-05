###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_virtualbox_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Oracle VM VirtualBox Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By:  Shakeel <bshakeel@secpod.com> on 2013-10-28
# According to cr57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902788";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-01-25 11:25:41 +0530 (Wed, 25 Jan 2012)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Oracle VM VirtualBox Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Oracle VM VirtualBox.

The script logs in via ssh, searches for folder 'VirtualBox.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Oracle VM VirtualBox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock) {
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}


## Get the version of VMware Fusion Version
ver = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                      "VirtualBox.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(ver) || "does not exist" >< ver){
  exit(0);
}

## build cpe and store it as host_detail
if(version_is_less(version:version, test_version:"3.2.0"))
{
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:sun:virtualbox:");
  if(!(cpe))
    cpe="cpe:/a:sun:virtualbox";

  if(cpe)
    register_product(cpe:cpe, location:"/Applications/VirtualBox.app", nvt:SCRIPT_OID);
  else
    cpe = "Failed";
}
else
{
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:oracle:vm_virtualbox:");
  if(!(cpe))
    cpe="cpe:/a:oracle:vm_virtualbox";

  if(cpe)
    register_product(cpe:cpe, location:"/Applications/VirtualBox.app", nvt:SCRIPT_OID);
  else
    cpe = "Failed";
}

## Set the version in KB
set_kb_item(name: "Oracle/VirtualBox/MacOSX/Version", value:ver);
log_message(data: build_detection_report(app: "Oracle VirtualBox",
                                         version: ver,
                                         install: "/Applications/VirtualBox.app",
                                         cpe: cpe,
                                         concluded: ver));


