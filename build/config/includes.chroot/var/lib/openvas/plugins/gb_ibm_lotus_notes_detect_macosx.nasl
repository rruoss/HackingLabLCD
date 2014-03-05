###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_detect_macosx.nasl 18 2013-10-27 14:14:13Z jan $
#
# IBM Lotus Notes Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "Detection of installed version of IBM Lotus Notes.

The script logs in via ssh, searches for folder 'Lotus Notes.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803217";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-23 15:23:23 +0530 (Wed, 23 Jan 2013)");
  script_name("IBM Lotus Notes Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of IBM Lotus Notes for Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "ssh_authorization_init.nasl");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
sock = 0;
cpe = "";
ver = "";
lotusVer = NULL;

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

## Get the version
lotusVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Lotus\\ Notes.app/Contents/Info CFBundleShortVersionString"));

## Close Socket
close(sock);

if(isnull(lotusVer) || "does not exist" >< lotusVer){
   exit(0);
}

if(lotusVer =~ "FP")
  lotusVer = ereg_replace(pattern:"FP", string:lotusVer, replace:".");

## Set the KB
set_kb_item(name: "IBM/LotusNotes/MacOSX/Ver", value:lotusVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:lotusVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:lotus_notes:");
if(isnull(cpe))
  cpe = "cpe:/a:ibm:lotus_notes";

lotusPath = "/Applications/Lotus Notes.app";
register_product(cpe:cpe, location:lotusPath, nvt:SCRIPT_OID);

log_message(data: build_detection_report(app: "IBM Lotus Notes",
                                         version:lotusVer,
                                         install:lotusPath,
                                         cpe:cpe,
                                         concluded: lotusVer));
