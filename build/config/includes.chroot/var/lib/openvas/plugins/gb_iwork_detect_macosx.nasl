###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iwork_detect_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# iWork Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed product version of iWork and sets
  the result in KB";

if(description)
{
  script_id(802145);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("iWork Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of of iWork in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Checking for Mac OS X
if(!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the iWork version
## For iWork, version is taken from any of its 3 components Keynote, Pages
## and Numbers. Taking version from Keynote Component
## Refer below wiki link for version mapping
## http://en.wikipedia.org/wiki/IWork

foreach ver (make_list("09","08", "07","06"))
{
  iworkVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "iWork\ \'"+ ver +"/Keynote.app/Contents/Info " +
                 "CFBundleShortVersionString"));

  if("does not exist" >!< iworkVer){
    break;
  }
}

## Close Socket
close(sock);

## Exit if version not found
if(isnull(iworkVer) || "does not exist" >< iworkVer){
  exit(0);
}

## Set the version in KB
set_kb_item(name: "Apple/iWork/Keynote/MacOSX/Version", value:iworkVer);
security_note(data:"Apple iWork keynote version " + iworkVer +
                  " was detected on this host");
