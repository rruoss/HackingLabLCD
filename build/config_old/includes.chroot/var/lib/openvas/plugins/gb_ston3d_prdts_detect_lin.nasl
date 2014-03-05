###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ston3d_prdts_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# StoneTrip Ston3D Standalone Player Version Detection (Lin)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed version of StoneTrip Ston3D
  Standalone Player and sets the result in KB.";

if(description)
{
  script_id(800575);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("StoneTrip Ston3D Standalone Player Version Detection (Lin)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of StoneTrip Ston3D Standalone Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800575";
SCRIPT_DESC = "StoneTrip Ston3D Standalone Player Version Detection (Lin)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("Standalone Engine [0-9.]\\+");

# Set KB for Standalone Engine
sapName = find_file(file_name:"S3DEngine_Linux", file_path:"/",
                      useregex:TRUE, regexpar:"$", sock:sock);
if(sapName != NULL)
{
  foreach binaryName (sapName)
  {
    binaryName = chomp(binaryName);
    if(islocalhost())
    {
      garg[4] = binaryName;
      arg = garg;
    }
    else
    {
      arg = garg[0]+" "+garg[1]+" "+garg[2]+" "+
            raw_string(0x22)+garg[3]+raw_string(0x22)+" "+binaryName;
    }

    sapVer = get_bin_version(full_prog_name:grep, version_argv:arg, sock:sock,
                               ver_pattern:"([0-9.]+)");
    if(sapVer[1] != NULL)
    {
      set_kb_item(name:"Ston3D/Standalone/Player/Lin/Ver", value:sapVer[1]);
      security_note(data:"StoneTrip Ston3D Standalone Player version " + sapVer[1] + 
                    " running at location " + binaryName + " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:sapVer[1], exp:"^([0-9.]+)", base:"cpe:/a:stonetrip:s3dplayer_standalone:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      break;
    }
  }
}
