###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_detect_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# LibreOffice Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "Detection of installed version of LibreOffice.

The script logs in via ssh, searches for folder 'LibreOffice.app' and
queries the related 'info.plist' file for string 'CFBundleVersion' via command
line option 'defaults read'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803063";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-26 17:26:43 +0530 (Mon, 26 Nov 2012)");
  script_name("LibreOffice Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of LibreOffice for Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
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
liboVer = NULL;

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock)
{
  close(sock);
  exit(0);
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

## Get the version of LibreOffice
liboVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "LibreOffice.app/Contents/Info CFBundleGetInfoString"));
if(isnull(liboVer) || "does not exist" >< liboVer){
   exit(0);
}

liboVer = eregmatch(pattern:"LibreOffice ([0-9.]+) .*(Build:([0-9.]+))", string:liboVer);

if(!liboVer){
  exit(0);
}

if(liboVer[1] && liboVer[3])
  buildVer = liboVer[1] + "." + liboVer[3];

set_kb_item(name: "LibreOffice/MacOSX/Version", value: liboVer[1]);
set_kb_item(name: "LibreOffice-Build/MacOSX/Version", value: buildVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:liboVer[1], exp:"^([0-9.]+)",
                   base:"cpe:/a:libreoffice:libreoffice:");
path = '/Applications/LibreOffice.app/';

if(isnull(cpe))
cpe = "cpe:/a:libreoffice:libreoffice";

register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

log_message(data: build_detection_report(app: "LibreOffice",
                                         version:liboVer[1],
                                         install:path,
                                         cpe:cpe,
                                         concluded: liboVer[1]));
