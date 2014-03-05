###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Adobe Flash Player/AIR Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modification for getting the path when it contains a space
#   - By Sharath S <sharaths@secpod.com> On 2009-07-27
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-18
# According to CR57 and new style script_tags.
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800032";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"detection", value:"executable version check");
  script_name("Adobe Flash Player/AIR Version Detection (Linux)");

  tag_summary =
"Detection of installed version of Adobe Flash Player/AIR on Windows.

The script logs in via ssh, extracts the version from the binary file
and set it in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set KB for the version of Adobe Flash Player/AIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("[0-9]\\+,[0-9]\\+,[0-9]\\+,[0-9]\\+");

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

## start script
air_sock = ssh_login_or_reuse_connection();
if(!air_sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:air_sock);
grep = chomp(grep[0]);

# Set KB for Adobe Flash Player
flashName = find_file(file_name:"libflashplayer.so", file_path:"/",
                      useregex:TRUE, regexpar:"$", sock:air_sock);
if(flashName != NULL)
{
  for(a = 0; a < max_index(flashName); a++)
  {
    ## Adobe AIR also has libflashplayer.so file
    ## So, Confirming that it is not Adobe AIR
    if("AIR" >!< flashName[a])
    {
      binaryName = ereg_replace(pattern:" ", replace:"\ ",
                                string:chomp(flashName[a]));

      arg = garg[0]+" "+garg[1]+" "+garg[2]+" "+
            raw_string(0x22)+garg[3]+raw_string(0x22)+" "+binaryName;

      flashVer = get_bin_version(full_prog_name:grep, version_argv:arg, sock:air_sock,
                                 ver_pattern:"([0-9]+,[0-9]+,[0-9]+,[0-9]+)");

      if(flashVer[0] != NULL)
      {
        flashVer = ereg_replace(pattern:",|_|-", string:flashVer[0], replace: ".");

        set_kb_item(name:"AdobeFlashPlayer/Linux/Ver", value:flashVer);

        ## Build CPE
        cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:flash_player";

        ## Register Product and Build Report
        build_report(app: "Adobe Flash Player", ver: flashVer, cpe: cpe, insloc: binaryName);
      }
    }
  }
}

# Set KB for Adobe AIR
airPaths = find_file(file_name:"ApolloVersion", file_path:"/",
                     useregex:TRUE, regexpar:"$", sock:air_sock);
if(airPaths != NULL)
{
  for(i = 0; i < max_index(airPaths); i++)
  {
    if("Adobe" >< airPaths[i])
    {
      airPath = ereg_replace(pattern:" ", replace:"\ ", string:airPaths[i]);
      airVer = get_bin_version(full_prog_name:"cat", version_argv:airPath,
                               ver_pattern:"([0-9.]+)", sock:air_sock);
      if(airVer[1] != NULL)
      {
        airVer = ereg_replace(pattern:",|_|-", string:airVer[1], replace: ".");

        set_kb_item(name:"Adobe/Air/Linux/Ver", value:airVer);

        ## Build CPE
        cpe = build_cpe(value:airVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:adobe_air:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:adobe_air";

        ## Register Product and Build Report
        build_report(app: "Adobe AIR", ver: airVer, cpe: cpe, insloc: airPath);
      }
    }
  }
}
ssh_close_connection();
