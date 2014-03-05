###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_professional_detect_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Flash Professional Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_summary = "Detection of installed version of Adobe Flash Professional.

The script logs in via ssh, searches for folder 'Adobe Flash CS.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802784";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-16 11:25:30 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Flash Professional Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Adobe Flash Professional for Mac OS X");
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
sock = "";
ver = "";
flashVer = "";
cpe = "";
path = "";

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock) {
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

## Checking for Mac OS X
if(!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

foreach ver (make_list("3", "4", "5", "5.5", "5.5.1", "6"))
{
  ## Get the version of Adobe Flash Professional
  flashVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Adobe\\ Flash\\ CS" + ver + "/Adobe\\ Flash\\ CS" + ver +
             ".app/Contents/Info CFBundleShortVersionString"));
  if(isnull(flashVer) || "does not exist" >< flashVer){
     continue;
  }

  ## Set the version in KB
  set_kb_item(name: "Adobe/Flash/Prof/MacOSX/Version", value:flashVer);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_cs"
                   + ver + ":");
  path = '/Applications/Adobe Flash CS' + ver;
  if(!isnull(cpe))
    register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
  else
    cpe = "Failed";

  log_message(data: build_detection_report(app:"Adobe Flash Professional",
                                         version:flashVer,
                                         install:path,
                                         cpe:cpe,
                                         concluded: flashVer));
}

close(sock);