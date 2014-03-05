###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# VLC Media Player Version Detection (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Shashi Kiran N <nskiran@secpod.com> on 2013-10-22
# According to new style script_tags.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900528";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("VLC Media Player Version Detection (Win)");

  tag_summary =
"Detection of installed version of VLC Media Player version on Windows.

The script logs in via smb, searches for Corel PDF Fusion in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set KB for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");


## Variable Initialization
vlcVer = "";
syskey = "";
vlcPath = "";

## Check Processor Architecture
syskey = "SOFTWARE\VideoLAN\VLC";
if(!registry_key_exists(key:syskey)) {
  exit(0);
}

vlcVer = registry_get_sz(item:"Version", key:syskey);
vlcPath = registry_get_sz(item:"InstallDir", key:syskey);

if(vlcVer != NULL && vlcPath != NULL)
{
  set_kb_item(name:"VLCPlayer/Win/Ver", value:vlcVer);

  ## build cpe
  cpe = build_cpe(value:vlcVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:videolan:vlc_media_player:");
  if(isnull(cpe))
     cpe = "cpe:/a:videolan:vlc_media_player";

  register_product(cpe:cpe, location:vlcPath, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: "VLC Media Player",
                                           version: vlcVer,
                                           install: vlcPath,
                                           cpe: cpe,
                                           concluded: vlcVer));

}
