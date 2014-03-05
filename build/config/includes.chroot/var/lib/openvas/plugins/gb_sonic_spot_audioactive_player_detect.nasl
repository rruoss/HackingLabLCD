###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonic_spot_audioactive_player_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sonic Spot Audioactive Player Version Detection
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
tag_summary = "This script detects the version of Sonic Spot Audioactive Player
  and sets the version in KB.";

if(description)
{
  script_id(800571);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sonic Spot Audioactive Player Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for the version of Sonic Spot Audioactive Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800571";
SCRIPT_DESC = "Sonic Spot Audioactive Player Version Detection";


## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}
key = "SOFTWARE\Telos Systems\Audioactive Player";
if(!registry_key_exists(key:key))exit(0);

foreach item (registry_enum_keys(key:key))
{
  audioactiveVer = eregmatch(pattern:"[0-9.]+[a-z]?", string:item);
  if(audioactiveVer != NULL)
  {
    set_kb_item(name:"SonicSpot/Audoiactive/Player/Ver", value:audioactiveVer[0]);
    security_note(data:"Sonic Spot Audioactive Player version " + audioactiveVer[0] +
                    " was detected on the host");
     
    ## build cpe and store it as host_detail
    register_cpe(tmpVers:audioactiveVer[0], tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:sonicspot:audioactive_player:");
    register_cpe(tmpVers:audioactiveVer[0], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:sonicspot:audioactive_player:");
    exit(0);
  }
}
