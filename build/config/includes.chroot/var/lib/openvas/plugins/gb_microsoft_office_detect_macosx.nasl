###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_office_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft Office Version Detection (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "Detection of installed version of Microsoft Office.

The script logs in via ssh, and searches for Microsoft Office '.app' folder
and queries the related 'Info.plist' file for string'CFBundleShortVersionString'
via command line option 'defaults read'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802431";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"executable version check");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-05-09 10:50:16 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Version Detection (Mac OS X)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Set the version of Microsoft Office for Mac in KB");
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

## Check for each OS
foreach offVer (make_list("2008", "2011"))
{
  offVersion = chomp(ssh_cmd(socket:sock, cmd:"defaults read  /Applications/" +
               "Microsoft\\ Office\\ " + offVer +  "/Microsoft\\ Document\\ " +
               "Connection.app/Contents/Info CFBundleShortVersionString"));

  if("does not exist" >< offVersion){
    continue;
  }

  if(offVersion)
  {
    set_kb_item(name: "MS/Office/MacOSX/Ver", value:offVersion);
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:offVersion, exp:"^([0-9.]+)",
                   base: "cpe:/a:microsoft:office:" + offVer + "::mac");
    if(!isnull(cpe))
    {
      location =  "/Applications/Microsoft\ Office\ " + offVer +
      "/Microsoft\ Document\ Connection.app/Contents/Info.plist";
      register_product(cpe:cpe, location:location, nvt:SCRIPT_OID);
    }
    else
      cpe = "Failed";

    log_message(data:'Detected Microsoft Office version: ' + offVersion + 'for Mac' +
    '\nLocation: ' + location +
    '\nCPE: '+ cpe +
    '\n\nConcluded from version identification result:\n' + offVersion);
  }
}

## Close Socket
close(sock);
