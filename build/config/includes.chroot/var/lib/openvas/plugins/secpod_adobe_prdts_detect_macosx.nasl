###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_detect_macosx.nasl 44 2013-11-04 19:58:48Z jan $
#
# Adobe Products Version Detection (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 20-09-2011
# -Updated to detect Adobe reader and acrobat versions
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 10-11-2011
# -Updated to detect Adobe Shockwave Player versions
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 09-12-2011
#  -Updated detect path for adobe/acrobat/Air and accoring CR57.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to new style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902711";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Adobe Products Version Detection (Mac OS X)");

  tag_summary =
"Detection of installed version of Adobe Products.

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
  script_summary("Detect the installed Adobe Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
airVer = "";
buffer = "";
version = "";
readerVer = "";
acrobatVer = "";

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
}

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock)
{
  if(defined_func("error_message"))
  {
    error_message(port:port, data:"Failed to open ssh port.");
    exit(-1);
  }
}

## Checking for Mac OS X
if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}


########################################
##
## Get the version of Adobe Flash Player
##
########################################
buffer = get_kb_item("ssh/login/osx_pkgs");
if(buffer != NULL)
{
  if("com.adobe.pkg.FlashPlayer" >< buffer)
  {
    ## Grep for the version
    version = eregmatch(pattern:"FlashPlayer[^\n]([0-9.]+)", string:buffer);
    if(version[1] != NULL)
    {
      ## Set the version in KB
      set_kb_item(name: "Adobe/Flash/Player/MacOSX/Version", value:version[1]);

      ## Build cpe
      cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player:");
      if(isnull(cpe))
        cpe = "cpe:/a:adobe:flash_player";

      ## Register Product and Build Report
      build_report(app: "Adobe Flash Player", ver: version[1], cpe: cpe,
                   insloc: "/Applications/Install Adobe Flash Player.app");
    }
  }
}


####################################
##
## Check for shockwave player
##
####################################
if("com.adobe.shockwave" >< buffer)
{
  ## Grep for the version
  version = eregmatch(pattern:"shockwave[^\n]([0-9.]+)", string:buffer);
  if(version[1] != NULL)
  {
    ## Set the version in KB
    set_kb_item(name: "Adobe/Shockwave/Player/MacOSX/Version", value:version[1]);

    ## Build cpe
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:shockwave_player:");
    if(isnull(cpe))
      cpe = "cpe:/a:adobe:shockwave_player";

    ## Register Product and Build Report
    build_report(app: "Adobe Shockwave Player", ver: version[1], cpe: cpe, insloc: "/Applications");
  }
}


####################################
##
## Get the version of Adobe Air
##
####################################
airVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
         "Adobe\\ AIR\\ Installer.app/Contents/Info " +
         "CFBundleShortVersionString"));

if(!isnull(airVer) && "does not exist" >!< airVer)
{
  ## Set the version in KB
  set_kb_item(name: "Adobe/Air/MacOSX/Version", value:airVer);

  ## Build cpe
  cpe = build_cpe(value:airVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:adobe_air:");
  if(isnull(cpe))
    cpe = "cpe:/a:adobe:adobe_air";

    ## Register Product and Build Report
    build_report(app: "Adobe Air", ver: airVer, cpe: cpe,
                 insloc: "/Applications/Adobe AIR Installer.app");
}


####################################
##
## Get the version of Adobe Reader
##
####################################
readerVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "Adobe\\ Reader.app/Contents/Info CFBundleShortVersionString"));

if(!isnull(readerVer) && "does not exist" >!< readerVer)
{
  ## Set the version in KB
  set_kb_item(name: "Adobe/Reader/MacOSX/Version", value:readerVer);

  ## Build cpe
  cpe = build_cpe(value:readerVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_reader:");
  if(isnull(cpe))
    cpe = "cpe:/a:adobe:acrobat_reader";

  ## Register Product and Build Report
  build_report(app: "Adobe Reader", ver: readerVer, cpe: cpe, insloc: "/Applications/Adobe Reader.app");
}


####################################
##
## Get the version of Adobe Acrobat
##
####################################
foreach ver (make_list("XI", "10", "9", "8"))
{
  acrobatVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
               "Adobe\\ Acrobat\\ " + ver + "\\ Pro/Adobe\\ Acrobat\\ Pro.app/" +
               "Contents/Info CFBundleShortVersionString"));
  if("does not exist" >!< acrobatVer){
       break;
  }
}

## Exit if version not found
if(!isnull(acrobatVer) && "does not exist" >!< acrobatVer)
{
  ## Set the version in KB
  set_kb_item(name: "Adobe/Acrobat/MacOSX/Version", value:acrobatVer);

  ## Build cpe
  cpe = build_cpe(value:acrobatVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat:");
  if(isnull(cpe))
    cpe = "cpe:/a:adobe:acrobat";

  ## Register Product and Build Report
  build_report(app: "Adobe Acrobat", ver: acrobatVer, cpe: cpe, insloc: "/Applications/Adobe Acrobat");
}

## Close Socket
close(sock);
