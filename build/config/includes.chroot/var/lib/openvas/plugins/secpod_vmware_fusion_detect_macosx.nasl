###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_fusion_detect_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# VMware Fusion Version Detection (Mac OS X)
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
tag_summary = "Detection of installed version of VMware Fusion.

The script logs in via ssh, searches for folder 'VMware Fusion.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902633";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-17 17:38:48 +0530 (Thu, 17 Nov 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_name("VMware Fusion Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of VMware Fusion");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

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

## Get the version of VMware Fusion Version
vmfusionVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                "VMware\\ Fusion.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

## Exit if version not found
if(isnull(vmfusionVer) || "does not exist" >< vmfusionVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "VMware/Fusion/MacOSX/Version", value:vmfusionVer);
log_message(data:'Detected VMware version: ' + vmfusionVer +
        '\nLocation: /Applications/VMware Fusion.app' +
        '\n\nConcluded from version identification result:\n' + "VMware Fusion " + vmfusionVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:vmfusionVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:fusion:");
if(!isnull(cpe))
  register_product(cpe:cpe, location:"/Applications/VMware Fusion.app", nvt:SCRIPT_OID);
else
  cpe = "Failed";
